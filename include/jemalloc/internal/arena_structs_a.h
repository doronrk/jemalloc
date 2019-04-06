#ifndef JEMALLOC_INTERNAL_ARENA_STRUCTS_A_H
#define JEMALLOC_INTERNAL_ARENA_STRUCTS_A_H

#include "jemalloc/internal/bitmap.h"
#include "jemalloc/internal/ql.h"

struct arena_slab_data_s {
	/* Per region allocated/deallocated bitmap. */
	bitmap_t	bitmap[BITMAP_GROUPS_MAX];
	// TODO pack this into bitmap somehow without UB
	ql_elm(extent_t)	ql_mesh_link;
};

#endif /* JEMALLOC_INTERNAL_ARENA_STRUCTS_A_H */
