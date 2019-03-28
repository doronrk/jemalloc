#define JEMALLOC_MESH_C_

#include "jemalloc/internal/jemalloc_preamble.h"
#include "jemalloc/internal/jemalloc_internal_includes.h"

#include "jemalloc/internal/log.h"

struct mesh_pair_s {
	extent_t *src;
	extent_t *dst;
};

typedef struct mesh_pair_s mesh_pair_t;

typedef size_t (mesh_get_candidate_arenas_t)(arena_t **candidates);
typedef size_t (mesh_get_candidate_scs_t)(arena_t *arena, size_t *candidates);
typedef bool (mesh_should_mesh_bin_t)(arena_t *arena, bin_t *bin);
typedef size_t (mesh_find_meshable_pairs_t)(arena_t *arena, bin_t *bin, mesh_pair_t **meshable_pairs);

struct mesh_hooks_s {
	mesh_get_candidate_arenas_t	*arenas;
	mesh_get_candidate_scs_t	*scs;
	mesh_should_mesh_bin_t		*bin;
	mesh_find_meshable_pairs_t	*find_pairs;
};

typedef struct mesh_hooks_s mesh_hooks_t;

const mesh_hooks_t mesh_hooks_default = {
	NULL,
	NULL,
	NULL,
	NULL
};

static void
mesh_pair(bin_t *bin, extent_t *src, extent_t *dst) {
	LOG("mesh", "meshing %p %p %p", bin, src, dst);	
}

static void
mesh_bin(arena_t *arena, bin_t *bin) {
	mesh_pair_t *meshable_pairs;
	size_t nmeshable_pairs = mesh_hooks_default.find_pairs(arena, bin, &meshable_pairs);
	for (size_t i = 0; i < nmeshable_pairs; i++) {
		mesh_pair_t *pair = &meshable_pairs[i];
		mesh_pair(bin, pair->src, pair->dst);
	}
}


static void
mesh_arena(arena_t *arena) {
	size_t scs[SC_NBINS];
	size_t nscs_to_mesh = mesh_hooks_default.scs(arena, scs);
	for (size_t i = 0; i < nscs_to_mesh; i++) {
		size_t sc = scs[i];
		bin_info_t *bin_info = &bin_infos[sc];
		bins_t *bins = &arena->bins[sc];
		for (size_t j = 0; j < bin_info->n_shards; j++) {
			bin_t *bin = &bins->bin_shards[j];
			// TODO lock bin here?  
			if (mesh_hooks_default.bin(arena, bin)) {
				mesh_bin(arena, bin);
			}
		}	
	}	
}

static void
mesh_mesh() {
	unsigned narenas = narenas_total_get();
	VARIABLE_ARRAY(arena_t *, arenas, narenas);
	size_t narenas_to_mesh = mesh_hooks_default.arenas(arenas);
	for (size_t i = 0; i < narenas_to_mesh; i++) {
		mesh_arena(arenas[i]);
	}		
}

void
mesh_boot(void) {
	LOG("doronrk", "mesh boot y'all");
	mesh_arena(NULL);
}
