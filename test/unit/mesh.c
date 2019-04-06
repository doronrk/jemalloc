#include "test/jemalloc_test.h"

static void 
integrity_check(mesh_arena_data_t *mesh_arena_data) {
#ifdef JEMALLOC_DEBUG
	assert(mesh_arena_data->magic == MESH_MAGIC);
	for (size_t i = 0; i < nmeshable_scs; i++) {
		mesh_bin_datas_t *bitmap_maps = &mesh_arena_data->bin_datas[i];
		assert(bitmap_maps->magic == MESH_MAGIC);
		unsigned binind = meshind_to_binind_table[i];
		bin_info_t *bin_info = &bin_infos[binind];
		for (size_t j = 0; j < bin_info->n_shards; j++) {
			mesh_bin_data_t *bitmap_map = &bitmap_maps->bin_data_shards[j];
			assert(bitmap_map->magic == MESH_MAGIC);
		}
	}
#endif
}

TEST_BEGIN(test_mesh_arena_data_new) {
	tsdn_t *tsdn = tsdn_fetch();
	base_t *base = base_new(tsdn, 0, (extent_hooks_t *)&extent_hooks_default);

	mesh_arena_data_t *mesh_arena_data = mesh_arena_data_new(tsdn, base);
	assert_ptr_not_null(mesh_arena_data, "Failed to allocate mesh_arena_data");
	integrity_check(mesh_arena_data);
}
TEST_END

TEST_BEGIN(test_mesh_arena_data_bitmap_insert_remove) {
	bin_info_t *bin_info = NULL;
	szind_t binind;
	for (size_t i = 0; i < SC_NBINS; i++) {
		if (bin_infos[i].nregs == 8) {
			bin_info = &bin_infos[i];
			binind = i;
			break;
		}
	}
	assert_ptr_not_null(bin_info, "No meshable size classes");
	extent_t slabs[1 << 8];
	for (size_t i = 0; i < 1 << 8; i++) {
		extent_init(&slabs[i], NULL, mallocx(bin_info->slab_size,
		    MALLOCX_LG_ALIGN(LG_PAGE)), bin_info->slab_size, true,
		    binind, 0, extent_state_active, false, true, true);
		extent_nfree_binshard_set(&slabs[i], bin_info->nregs, 0);
		assert_ptr_not_null(extent_addr_get(&slabs[i]),
			"Unexpected malloc() failure");
		assert(mesh_slab_is_candidate(&slabs[i]));
	}
	
	tsdn_t *tsdn = tsdn_fetch();
	base_t *base = base_new(tsdn, 0, (extent_hooks_t *)&extent_hooks_default);

	mesh_arena_data_t *mesh_arena_data = mesh_arena_data_new(tsdn, base);
	assert_ptr_not_null(mesh_arena_data, "Failed to allocate mesh_arena_data");

	for (size_t i = 0 ; i < 1 << 8; i++) {
		if (i == 0x0 || i == 0xff) {
			continue;
		}
		extent_t *slab = &slabs[i];
		arena_slab_data_t *slab_data = extent_slab_data_get(slab);
		uint8_t key = (uint8_t)i;
		slab_data->bitmap[0] = key;
		unsigned nfree = 0;
		for (size_t j = 0; j < bin_info->nregs; j++) {
			if (bitmap_get(slab_data->bitmap, &bin_info->bitmap_info, j)) {
				nfree++;
			}
		}
		extent_nfree_set(slab, nfree);
		mesh_slab_bitmap_update(mesh_arena_data, slab_data, bin_info, slab);
	}
	integrity_check(mesh_arena_data);
	for (size_t i = 0 ; i < 1 << 8; i++) {
		if (i == 0x0 || i == 0xff) {
			continue;
		}
		extent_t *slab = &slabs[i];	
		arena_slab_data_t *slab_data = extent_slab_data_get(slab);
		mesh_slab_bitmap_invalidate(mesh_arena_data, slab_data, bin_info, slab);
	}
	integrity_check(mesh_arena_data);
}
TEST_END

int
main(void) {
	return test(
	    test_mesh_arena_data_new,
	    test_mesh_arena_data_bitmap_insert_remove);
}
