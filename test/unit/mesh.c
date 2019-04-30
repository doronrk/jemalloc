#include "test/jemalloc_test.h"

#include "jemalloc/internal/mesh.h"

TEST_BEGIN(test_mesh_populate_bin_data) {
	size_t sz;

	mesh_boot();

	/* Make sure allocation below isn't satisfied by tcache. */
	assert_d_eq(mallctl("thread.tcache.flush", NULL, NULL, NULL, 0),
	    opt_tcache ? 0 : EFAULT, "Unexpected mallctl() result");

	unsigned arena_ind, old_arena_ind;
	sz = sizeof(unsigned);
	assert_d_eq(mallctl("arenas.create", (void *)&arena_ind, &sz, NULL, 0),
	    0, "Arena creation failure");
	sz = sizeof(arena_ind);
	assert_d_eq(mallctl("thread.arena", (void *)&old_arena_ind, &sz,
	    (void *)&arena_ind, sizeof(arena_ind)), 0,
	    "Unexpected mallctl() failure");

	tsdn_t *tsdn = tsdn_fetch();
	arena_t *arena = arena_get(tsdn, arena_ind, false);
	assert(arena != NULL);

	szind_t binind;
	for (binind = 0; binind < SC_NBINS; binind++) {
		if (bin_infos[binind].reg_size == 2048) {
			break;
		}
	}

	assert(mesh_binind_meshable(binind));

	void *ptrs[128];
	for (size_t i = 0; i < 128; i++) {
		ptrs[i] = malloc(2048);
		assert_ptr_not_null(ptrs[i], "Unexpected malloc() failure");
	}

	for (size_t i = 0; i < 64; i++) {
		size_t ind = (i * 2) + (i % 2);
		dallocx(ptrs[ind], 0);
	}

	assert_d_eq(mallctl("thread.tcache.flush", NULL, NULL, NULL, 0),
	    opt_tcache ? 0 : EFAULT, "Unexpected mallctl() result");

	mesh_bin_data_t mesh_bin_data;

	const bitmap_info_t *binfo = &bin_infos[binind].bitmap_info;
	unsigned binshard;
	bin_t *bin = arena_bin_choose_lock(tsdn, arena, binind, &binshard);
	assert(bin != NULL);
	malloc_mutex_unlock(tsdn, &bin->lock);

	mesh_populate_bin_data(bin, binfo, &mesh_bin_data);
	mesh_populate_bin_data(bin, binfo, &mesh_bin_data);

	for (size_t i = 0; i < 32; i++) {
		size_t ind = (i * 2) + ((i + 1) % 2);
		dallocx(ptrs[ind], 0);
	}

	mesh_populate_bin_data(bin, binfo, &mesh_bin_data);

	for (size_t i = 32; i < 64; i++) {
		size_t ind = (i * 2) + ((i + 1) % 2);
		dallocx(ptrs[ind], 0);
	}

	mesh_populate_bin_data(bin, binfo, &mesh_bin_data);
}
TEST_END

int
main(void) {
	return test_no_reentrancy(
	    test_mesh_populate_bin_data);
}
