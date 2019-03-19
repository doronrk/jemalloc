#include <iostream>
#include <jemalloc/jemalloc.h>
#include <cstdlib>
#include <cstring>
#include <thread>
#include <vector>
#include <cassert>

void mesh_test() {
	void* mem1a = malloc(2048);
	void* mem1b = malloc(2048);
	void* mem2a = malloc(2048);
	void* mem2b = malloc(2048);

	std::cout << "mem1a: " << mem1a << std::endl;
	std::cout << "mem1b: " << mem1b << std::endl;
	std::cout << "mem2a: " << mem2a << std::endl;
	std::cout << "mem2b: " << mem2b << std::endl;

	strcpy((char*)mem1a, "mem1a");
	strcpy((char*)mem2b, "mem2b");

	free(mem1b);
	free(mem2a);

	// Should be meshed here

	free(mem1a);
	free(mem2b);
}

void flush() {
	int num = 11;
	std::vector<void*> ptrs;
	auto talloc = std::thread([num, &ptrs](){
		for (int i = 0; i < num; i++) {
			void *ptr = malloc(2048);
			assert(ptr != nullptr);
			ptrs.push_back(ptr);	
		}
	});
	
	talloc.join();

	void* singleptr = malloc(2048);
	free(singleptr);

	for (void* ptr : ptrs) {
		free(ptr);
	}
}

int main(int argc, char** argv) {
	doronrk_mesh();
	//malloc_stats_print(NULL, NULL, NULL);
	std::cout << "ran the program" << std::endl;
	return 0;
}
