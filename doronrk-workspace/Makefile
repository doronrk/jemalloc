CC=g++
CFLAGS=-I.

jemalloc_mesh: jemalloc_mesh.o
	$(CC) -o build/jemalloc_mesh jemalloc_mesh.o -L`jemalloc-config --libdir` -Wl,-rpath,`jemalloc-config --libdir` -ljemalloc `jemalloc-config --libs` && rm jemalloc_mesh.o

run:
	MALLOC_CONF="log:$(log)" ./build/jemalloc_mesh

gdb:
	MALLOC_CONF="log:$(log)" gdb ./build/jemalloc_mesh

jem:
	cd ../ && sudo make && sudo make install

cfg:
	cd ../ && ./configure --enable-debug --enable-log
