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
void *mesh_file_base;
int mesh_file_fd;
// Make this configurable?
size_t mesh_file_size = (1l << 30) * 256; // 256 GB
// num wasted bytes due to fragmentation caused by alignment
size_t bump_frag_bytes;

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
	return false;
}
