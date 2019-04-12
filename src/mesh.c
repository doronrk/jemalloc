#define JEMALLOC_MESH_C_
#include "jemalloc/internal/jemalloc_preamble.h"
#include "jemalloc/internal/jemalloc_internal_includes.h"

#include "jemalloc/internal/mesh.h"

#include "jemalloc/internal/log.h"

#include <linux/memfd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <bits/syscall.h>

bool opt_mesh = true;

malloc_mutex_t alloc_lock;
uintptr_t next_alloc;
unsigned nmeshable_scs;
unsigned nmeshable_bins_per_arena;
unsigned binind_to_meshind_table[SC_NBINS];
unsigned meshind_to_binind_table[SC_NBINS]; // (SC_NBINS - nmeshable_scs) unused at end

void *mesh_file_base;
int mesh_file_fd;
// Make this configurable?
size_t mesh_file_size = (1l << 30) * 256; // 256 GB
// num wasted bytes due to fragmentation caused by alignment
size_t bump_frag_bytes;


static void
mesh_extents(extent_t *extent_a, extent_t *extent_b) {
	// TODO if opt_mesh_dry_run, fill out stats and return early
	LOG("mesh", "would have meshed extents");
}


static void
mesh_lists(mesh_bin_data_t *bin_data, uint8_t keya, uint8_t keyb) {
	extent_list_t *extents_a = &bin_data->table[keya];
	extent_list_t *extents_b = &bin_data->table[keyb];
	extent_t *extent_a;
	extent_t *extent_b;
	while (((extent_a = extent_mesh_list_first(extents_a)) != NULL) &&
		((extent_b = extent_mesh_list_first(extents_b)) != NULL)) {
		// TODO assert that bitmap fullness corresponds to keya and keyb
		extent_mesh_list_remove(extents_a, extent_a);
		extent_mesh_list_remove(extents_b, extent_b);
		mesh_extents(extent_a, extent_b);
		// TODO add these extents to some other list
		// perhaps arena->mesh_arena_data.mesh_bin_data[binind].shards[binshard].meshed_extents
	}	
}

void
mesh_bin(bin_t *bin, mesh_bin_data_t *bin_data) {
	LOG("mesh", "bin has nextents_total: %u", bin_data->nextents_total);
	assert(bin->slabs_nonfull_size == bin_data->nextents_total);
	/*
	if (bin_data->nextents_total == 0) {
		assert(bin->slabs_nonfull.ph_root == NULL);
	} else {
		assert(bin->slabs_nonfull.ph_root != NULL);
	}
	*/
	/*
	// bin must be locked
	for (uint8_t key = 0xfe; key >= 0x80; key--) {
		uint8_t compliment = ~key;
		while (compliment > 0) {
			if ((compliment & key) == 0) {
				LOG("mesh.lists", "key: %x comp: %d", key, compliment);
				mesh_lists(bin_data, key, compliment);
			}
			compliment--;
		}	
	}
	*/
}

void
mesh_arena(tsdn_t *tsdn, arena_t *arena) {
	bin_t *bin;
	mesh_bin_data_t *bin_data;
	mesh_arena_data_t *data = arena->mesh_arena_data;

	for (unsigned meshind = 0; meshind < nmeshable_scs; meshind++) {
		szind_t binind = meshind_to_binind_table[meshind];
		bin_info_t *bin_info = &bin_infos[binind];
		LOG("mesh.bin", "\tmeshing meshind: %u binind: %u", meshind, binind);
		for (unsigned binshard = 0; binshard < bin_info->n_shards; binshard++) {
			bin_data = &data->bin_datas[meshind].bin_data_shards[binshard];
			bin = &arena->bins[binind].bin_shards[binshard];
				
			malloc_mutex_lock(tsdn, &bin->lock);
			mesh_bin(bin, bin_data);			
			malloc_mutex_unlock(tsdn, &bin->lock);	
		}	
	}
	LOG("mesh", "\n");
}

JEMALLOC_EXPORT void JEMALLOC_NOTHROW
je_mesh_all_arenas() {
	unsigned narenas, i;
	tsdn_t *tsdn;
	tsd_t *tsd;

	LOG("mesh", "about to mesh all arenas");
	tsdn = tsdn_fetch();
	assert(tsdn != NULL);
	tsd = tsdn_tsd(tsdn);
	
	tcache_flush(tsd);

	for (i = 0, narenas = narenas_total_get(); i < narenas; i++) {
		arena_t *arena = arena_get(tsdn, i, false);
		if (arena != NULL) {
			LOG("mesh.arena", "meshing arena ind: %u", i);
			mesh_arena(tsdn, arena);
		}
	}
}

static off_t
addr_to_offset(void *addr) {
	assert((uintptr_t)addr >= (uintptr_t)mesh_file_base && (uintptr_t)addr < ((uintptr_t)mesh_file_base + mesh_file_size));
	return (uintptr_t)addr - (uintptr_t)mesh_file_base;
}

int
mesh_extent_destroy(void *addr, size_t size) {
	off_t offset = addr_to_offset(addr);
	return fallocate(mesh_file_fd, (FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE), offset, size);
}

bool
mesh_extent_in_meshable_area(void *addr, size_t size) {
	uintptr_t begin = (uintptr_t)addr;
	uintptr_t end = begin + size;
	uintptr_t mesh_begin = (uintptr_t)mesh_file_base;
	uintptr_t mesh_end = mesh_begin + mesh_file_size;

	if (begin >= mesh_begin && end <= mesh_end) {
		return true;
	}
	assert((begin < mesh_begin && end < mesh_begin) ||
	    (begin >= mesh_end && end >= mesh_end));
	return false;
}

bool
mesh_slab_is_candidate(extent_t *slab) {
	szind_t binind = extent_szind_get(slab);
	unsigned meshind = binind_to_meshind_table[binind];
	assert(meshind < nmeshable_scs || meshind == SC_NBINS);
	return meshind != SC_NBINS;
}

static void
insert_into_bin_data(mesh_bin_data_t *bin_data, uint8_t key, extent_t *slab) {
	bin_data->nextents_total++;
	bin_data->lengths[key]++;
	extent_mesh_list_append(&bin_data->table[key], slab);
}

static void
remove_from_bin_data(mesh_bin_data_t *bin_data, uint8_t key, extent_t *slab) {
	assert(bin_data->lengths[key] != 0);
	assert(bin_data->nextents_total != 0);
	bin_data->lengths[key]--;
	bin_data->nextents_total--;
	extent_mesh_list_remove(&bin_data->table[key], slab);
}

static mesh_bin_data_t *
get_map_for_slab(mesh_arena_data_t *data, const bin_info_t *bin_info, extent_t *slab) {
	szind_t binind = extent_szind_get(slab);
	unsigned meshind = binind_to_meshind_table[binind];
	assert(meshind != SC_NBINS);
	unsigned shard = extent_binshard_get(slab);
	return &data->bin_datas[meshind].bin_data_shards[shard];
}

void
mesh_slab_bitmap_update(mesh_arena_data_t *data, arena_slab_data_t *slab_data, const bin_info_t *bin_info, extent_t *slab) {
	assert(!bitmap_full(slab_data->bitmap, &bin_info->bitmap_info));
	assert(extent_nfree_get(slab) != bin_info->nregs);

	mesh_bin_data_t *bin_data = get_map_for_slab(data, bin_info, slab);
	uint8_t key = bitmap_get_logical_first_byte(slab_data->bitmap, &bin_info->bitmap_info);
	insert_into_bin_data(bin_data, key, slab);
}

void
mesh_slab_bitmap_invalidate(mesh_arena_data_t *data, arena_slab_data_t *slab_data, const bin_info_t *bin_info, extent_t *slab) {
	assert(!bitmap_full(slab_data->bitmap, &bin_info->bitmap_info));
	assert(extent_nfree_get(slab) != bin_info->nregs);

	mesh_bin_data_t *bin_data = get_map_for_slab(data, bin_info, slab);
	uint8_t key = bitmap_get_logical_first_byte(slab_data->bitmap, &bin_info->bitmap_info);
	remove_from_bin_data(bin_data, key, slab);
}

static void
bin_data_init(mesh_bin_data_t *bin_data) {
#ifdef JEMALLOC_DEBUG
	bin_data->magic = MESH_MAGIC;
#endif
	for (size_t i = 0; i < (1 << 8); i++) {
		extent_list_init(&bin_data->table[i]);
		bin_data->lengths[i] = 0;
	}
	bin_data->nextents_total = 0;
}
	
mesh_arena_data_t *
mesh_arena_data_new(tsdn_t *tsdn, base_t *base) {
	size_t size = sizeof(mesh_arena_data_t) + nmeshable_scs * sizeof(mesh_bin_datas_t);
	mesh_arena_data_t *arena_data = (mesh_arena_data_t *)base_alloc(tsdn, base, size, CACHELINE);
#ifdef JEMALLOC_DEBUG
	arena_data->magic = MESH_MAGIC;
#endif
	arena_data->bin_datas = (mesh_bin_datas_t *)(arena_data + 1);

	size = sizeof(mesh_bin_data_t) * nmeshable_bins_per_arena;
	
	mesh_bin_data_t *bin_data_base = (mesh_bin_data_t *)base_alloc(tsdn, base, size, CACHELINE);
	uintptr_t bin_data_addr = (uintptr_t)bin_data_base;
	
	for (size_t i = 0; i < nmeshable_scs; i++) {
		arena_data->bin_datas[i].bin_data_shards = (mesh_bin_data_t *)bin_data_addr;
#ifdef JEMALLOC_DEBUG
		arena_data->bin_datas[i].magic = MESH_MAGIC;
#endif
		unsigned binind = meshind_to_binind_table[i];
		bin_data_addr += sizeof(mesh_bin_data_t) * bin_infos[binind].n_shards;
	}
	assert(bin_data_addr == (uintptr_t)bin_data_base + size);

	for (size_t i = 0; i < nmeshable_bins_per_arena; i++) {
		bin_data_init(&bin_data_base[i]);
	}	
	return arena_data;
}

void *
mesh_extent_alloc(void *new_addr, size_t size, size_t alignment, bool *zero,
    bool *commit) {

	assert(next_alloc != 0x0);
	assert(new_addr == NULL);
	assert((size & PAGE_MASK) == 0);
	// TODO cp asserts from os_pages_map

	malloc_mutex_lock(TSDN_NULL, &alloc_lock);

	uintptr_t ret = ALIGNMENT_CEILING(next_alloc, alignment);
	if (ret + size > (uintptr_t)mesh_file_base + mesh_file_size) {
		malloc_mutex_unlock(TSDN_NULL, &alloc_lock);
		return NULL;
	}

	bump_frag_bytes += (ret - next_alloc);
	next_alloc = ret + size;

	malloc_mutex_unlock(TSDN_NULL, &alloc_lock);
	assert(ret % alignment == 0);
	
	// TODO this needs to be avoided if program is using tons of memory...
	assert(ret >= (uintptr_t)mesh_file_base && (ret + size <= (uintptr_t)mesh_file_base + mesh_file_size));
	if (os_overcommits) {
		*commit = true; // TODO doronk maybe do nothing to both zero and commit?
	}
	return (void *)ret;
}

bool
mesh_is_booted(void) {
	malloc_mutex_lock(TSDN_NULL, &alloc_lock);
	bool ret = next_alloc != 0x0;
	malloc_mutex_unlock(TSDN_NULL, &alloc_lock);
	return ret;
}

void
mesh_prefork(tsdn_t *tsdn) {
	malloc_mutex_prefork(tsdn, &alloc_lock);
}

void
mesh_postfork_parent(tsdn_t *tsdn) {
	malloc_mutex_postfork_parent(tsdn, &alloc_lock);
}

void
mesh_postfork_child(tsdn_t *tsdn) {
	malloc_mutex_postfork_child(tsdn, &alloc_lock);
}

bool
mesh_boot(void) {
	mesh_file_fd = syscall(__NR_memfd_create, "jemalloc_mesh_extent_slab", MFD_CLOEXEC);
	int ret = ftruncate(mesh_file_fd, mesh_file_size);
	assert(!ret);
	// Get linear layout of file in virtual address space
	mesh_file_base = mmap(NULL, mesh_file_size, (PROT_READ | PROT_WRITE), MAP_SHARED, mesh_file_fd, 0);
	// TODO proper error check on this addr for -1
	assert(mesh_file_base != NULL);
	// Free physical resources
	ret = fallocate(mesh_file_fd, (FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE), 0, mesh_file_size);
	assert(!ret);
	
	next_alloc = (uintptr_t)mesh_file_base;
	bump_frag_bytes = 0;
	malloc_mutex_init(&alloc_lock, "mesh_alloc_lock", WITNESS_RANK_OMIT, malloc_mutex_rank_exclusive);
	
	nmeshable_scs = 0;	
	nmeshable_bins_per_arena = 0;
	for (size_t i = 0; i < SC_NBINS; i++) {
		if (bin_infos[i].nregs <= 8 && bin_infos[i].nregs > 1) {
			meshind_to_binind_table[nmeshable_scs] = i; 
			binind_to_meshind_table[i] = nmeshable_scs++;
			nmeshable_bins_per_arena += bin_infos[i].n_shards;
		} else {
			binind_to_meshind_table[i] = SC_NBINS;
		}
	}

	for (size_t i = nmeshable_scs; i < SC_NBINS; i++) {
		meshind_to_binind_table[nmeshable_scs] = SC_NBINS; 
	}

	assert(nmeshable_scs > 0);

	return false;
}
