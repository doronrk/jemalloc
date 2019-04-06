#ifndef JEMALLOC_INTERNAL_MESH_H
#define JEMALLOC_INTERNAL_MESH_H

int
mesh_extent_destroy(void *addr, size_t size);

bool
mesh_extent_in_meshable_area(void *addr, size_t size);

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
