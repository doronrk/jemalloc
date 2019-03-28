CC=g++
CFLAGS=-g -std=c++11 -Wall -pedantic
 
jemalloc_mesh:
	$(CC) $(CFLAGS) -o build/jemalloc_mesh -L`jemalloc-config --libdir` -Wl,-rpath,`jemalloc-config --libdir` -ljemalloc `jemalloc-config --libs` jemalloc_mesh.cpp 

run:
	MALLOC_CONF="log:mesh" ./build/jemalloc_mesh
	#MALLOC_CONF="log:$(log)" ./build/jemalloc_mesh

gdb:
	MALLOC_CONF="log:$(log)" gdb ./build/jemalloc_mesh

jem:
	cd ../ && make && make dist && sudo make install

cfg:
	cd ../ && ./autogen.sh --enable-debug --enable-log
