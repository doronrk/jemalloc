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
	void* singleptr = malloc(2048);
	free(singleptr);

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


	for (int i = 0; i < 11; i++) {
		free(ptrs[11 - 1 - i]);
	}
	doronrk_mesh();
}

void allocate_some() {
	void *ptrs[100];
	for (int i = 0; i < 100; i++) {
		ptrs[i] = malloc(2048);
	}
	for (int i = 0; i < 50; i++) {
		free(ptrs[i * 2 + i % 2]);
	}
	doronrk_mesh();
	for (int i = 0; i < 50; i++) {
		free(ptrs[i * 2 + ((i + 1) % 2)]);
	}
}

int main(int argc, char** argv) {
	allocate_some();
	std::cout << "ran the program" << std::endl;
	return 0;
}
