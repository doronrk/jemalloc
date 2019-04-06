#ifndef JEMALLOC_INTERNAL_MESH_H
#define JEMALLOC_INTERNAL_MESH_H

extern bool opt_mesh;
extern unsigned nmeshable_scs;
extern unsigned binind_to_meshind_table[];
extern unsigned meshind_to_binind_table[];
extern size_t mesh_file_size;
extern void *mesh_file_base;

#define MESH_MAGIC 0x12341234

typedef struct mesh_bin_data_s mesh_bin_data_t;
struct mesh_bin_data_s {
	extent_list_t	table[1 << 8];
#ifdef JEMALLOC_DEBUG
	uint32_t magic;
#endif	
};

typedef struct mesh_bin_datas_s mesh_bin_datas_t;
struct mesh_bin_datas_s {
	mesh_bin_data_t *bin_data_shards;
#ifdef JEMALLOC_DEBUG
	uint32_t magic;
#endif	
};

typedef struct mesh_arena_data_s mesh_arena_data_t;
struct mesh_arena_data_s {
	mesh_bin_datas_t *bin_datas;
#ifdef JEMALLOC_DEBUG
	uint32_t magic;
#endif	
};

int
mesh_extent_destroy(void *addr, size_t size);

bool
mesh_extent_in_meshable_area(void *addr, size_t size);

bool 
mesh_slab_is_candidate(extent_t *slab);

void
mesh_slab_bitmap_update(mesh_arena_data_t *data, arena_slab_data_t *slab_data, const bin_info_t *bin_info, extent_t *slab);

void
mesh_slab_bitmap_invalidate(mesh_arena_data_t *data, arena_slab_data_t *slab_data, const bin_info_t *bin_info, extent_t *slab);

mesh_arena_data_t *
mesh_arena_data_new(tsdn_t *tsdn, base_t *base);

void *
mesh_extent_alloc(void *new_addr, size_t size, size_t alignment,
    bool *zero, bool *commit);

bool
mesh_is_booted(void);

void
mesh_prefork(tsdn_t *tsdn);

void
mesh_postfork_parent(tsdn_t *tsdn);

void
mesh_postfork_child(tsdn_t *tsdn);

bool mesh_boot(void);

#endif /* JEMALLOC_INTERNAL_MESH_EXTERNS_H */
