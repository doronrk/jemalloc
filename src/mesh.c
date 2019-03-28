#define JEMALLOC_MESH_C_

#include "jemalloc/internal/jemalloc_preamble.h"
#include "jemalloc/internal/jemalloc_internal_includes.h"

#include "jemalloc/internal/log.h"

struct mesh_pair_s {
	extent_t *src;
	extent_t *dst;
};

typedef struct mesh_pair_s mesh_pair_t;

static size_t mesh_arena_candidates_default(arena_t **candidates);
static size_t mesh_sc_candidates_default(arena_t *arena, size_t *candidates);
static bool mesh_bin_is_candidate_default(arena_t *arena, bin_t *bin, bin_info_t *bin_info);
static size_t mesh_find_pairs_default(arena_t *arena, bin_t *bin, bin_info_t *bin_info, mesh_pair_t **meshable_pairs);

typedef size_t (mesh_get_candidate_arenas_t)(arena_t **candidates);
typedef size_t (mesh_get_candidate_scs_t)(arena_t *arena, size_t *candidates);
typedef bool (mesh_should_mesh_bin_t)(arena_t *arena, bin_t *bin, bin_info_t *bin_info);
typedef size_t (mesh_find_meshable_pairs_t)(arena_t *arena, bin_t *bin, bin_info_t *bin_info, mesh_pair_t **meshable_pairs);

struct mesh_hooks_s {
	mesh_get_candidate_arenas_t	*arena_candidates;
	mesh_get_candidate_scs_t	*sc_candidates;
	mesh_should_mesh_bin_t		*bin_is_candidate;
	mesh_find_meshable_pairs_t	*find_pairs;
};

typedef struct mesh_hooks_s mesh_hooks_t;

const mesh_hooks_t mesh_hooks_default = {
	mesh_arena_candidates_default,
	mesh_sc_candidates_default,
	mesh_bin_is_candidate_default,
	mesh_find_pairs_default
};

static size_t 
mesh_arena_candidates_default(arena_t **candidates) {
	// TODO
	candidates[0] = arena_get(NULL, 0, false);
	return 1;
}
 
static size_t 
mesh_sc_candidates_default(arena_t *arena, size_t *candidates) {
	// TODO
	candidates[0] = 24; // 2048 byte sc
	return 1;
}

static bool 
mesh_bin_is_candidate_default(arena_t *arena, bin_t * bin, bin_info_t *bin_info) {
	// TODO
	return true;	
}

static bool
extents_are_meshable(bin_info_t *bin_info, extent_t *a, extent_t *b) {
	// TODO optimize this
	arena_slab_data_t *slab_data_a = extent_slab_data_get(a);
	arena_slab_data_t *slab_data_b = extent_slab_data_get(b);
	bitmap_info_t *bm_info = &bin_info->bitmap_info;
	for (size_t i = 0; i < bm_info->nbits; i++) {
		if (bitmap_get(slab_data_a->bitmap, bm_info, i) &&
			bitmap_get(slab_data_b->bitmap, bm_info, i)) {
			return false;
		}
	}
	return true;
}

mesh_pair_t mesh_pair_buf[512];
extent_t* extent_buf[1024];

static void 
fill_nonfull_helper(extent_t *extent, extent_t **buf, size_t *index, size_t buflen) {
	assert(extent != NULL);
	assert(*index != buflen);
	
	buf[*index] = extent;
	*index = *index + 1;
	if (*index == buflen) {
		return;
	}
	extent_t *leftmost_child = phn_lchild_get(extent_t, ph_link, extent);
	if (leftmost_child == NULL) {
		return;
	}
	fill_nonfull_helper(leftmost_child, buf, index, buflen);
	if (*index == buflen) {
		return;
	}
	extent_t *sibling;
	for (sibling = phn_next_get(extent_t, ph_link, leftmost_child); sibling !=
		NULL; sibling = phn_next_get(extent_t, ph_link, sibling)) {
		if (*index == buflen) {
			return;
		}
		fill_nonfull_helper(sibling, buf, index, buflen);
	}		
}

static size_t
fill_nonfull(bin_t *bin, extent_t **extent_buf, size_t buflen) {
	extent_heap_t* slabs_nonfull = &bin->slabs_nonfull;
	if (slabs_nonfull->ph_root == NULL || buflen == 0) {
		return 0;
	}
	size_t ret = 0;
	fill_nonfull_helper(slabs_nonfull->ph_root, extent_buf, &ret, 1024);
	extent_t *auxelm;
	for (auxelm = phn_next_get(extent_t, ph_link, slabs_nonfull->ph_root); auxelm != NULL && ret != buflen;
		auxelm = phn_next_get(extent_t, ph_link, auxelm)) {
		fill_nonfull_helper(auxelm, extent_buf, &ret, 1024);	
	}
	return ret;
} 

static size_t 
mesh_find_pairs_default(arena_t *arena, bin_t *bin, bin_info_t *bin_info, mesh_pair_t **meshable_pairs) {
	*meshable_pairs = mesh_pair_buf;
	size_t ret = 0;
	size_t nextents = fill_nonfull(bin, extent_buf, 1024);
	LOG("mesh", "grabbed %lu extents from nonfull", nextents);
	// fill up buf with top 1024 from nonfull
	// nested for loop
	size_t tunable = 64;
	size_t outer = nextents < tunable ? nextents : tunable;
	for (size_t i = 0; i < outer; i++) {
		for (size_t j = 0; j < nextents / 2; j++) {
			extent_t *a = extent_buf[j];
			extent_t *b = extent_buf[((nextents / 2)	+ j + i) % nextents];
			if (a == NULL || b == NULL) {
				continue;
			}
			if (extents_are_meshable(bin_info, a, b)) {
				mesh_pair_buf[ret].src = a;
				mesh_pair_buf[ret].dst = b;
				ret++;	
				extent_buf[j] = NULL;
				extent_buf[((nextents / 2) + j + i) % nextents] = NULL;
			}
		}	
	} 
	return ret;
}

/*
static void
mesh_pair(bin_t *bin, extent_t *src, extent_t *dst) {
	LOG("mesh", "meshing %p %p %p", bin, src, dst);	
}
*/

static void
mesh_bin(arena_t *arena, bin_t *bin, bin_info_t *bin_info) {
	mesh_pair_t *meshable_pairs;
	size_t nmeshable_pairs = mesh_hooks_default.find_pairs(arena, bin, bin_info, &meshable_pairs);
	LOG("mesh", "in bin: %p \twould have meshed npairs: %lu", bin, nmeshable_pairs);
	/*
	for (size_t i = 0; i < nmeshable_pairs; i++) {
		mesh_pair_t *pair = &meshable_pairs[i];
		mesh_pair(bin, pair->src, pair->dst);
	}
	*/
}


static void
mesh_arena(arena_t *arena) {
	LOG("mesh", "meshing arena: %p", arena);
	size_t scs[SC_NBINS];
	size_t nscs_to_mesh = mesh_hooks_default.sc_candidates(arena, scs);
	for (size_t i = 0; i < nscs_to_mesh; i++) {
		size_t sc = scs[i];
		bin_info_t *bin_info = &bin_infos[sc];
		bins_t *bins = &arena->bins[sc];
		for (size_t j = 0; j < bin_info->n_shards; j++) {
			bin_t *bin = &bins->bin_shards[j];
			// TODO lock bin here?  
			if (mesh_hooks_default.bin_is_candidate(arena, bin, bin_info)) {
				mesh_bin(arena, bin, bin_info);
			}
		}	
	}	
}

static void
mesh_mesh() {
	unsigned narenas = narenas_total_get();
	VARIABLE_ARRAY(arena_t *, arenas, narenas);
	size_t narenas_to_mesh = mesh_hooks_default.arena_candidates(arenas);
	for (size_t i = 0; i < narenas_to_mesh; i++) {
		mesh_arena(arenas[i]);
	}		
}

JEMALLOC_EXPORT void
je_mesh() {
	LOG("mesh", "beginning mesh routine");
	mesh_mesh();
}


void
mesh_boot(void) {
	LOG("doronrk", "mesh boot y'all");
}
