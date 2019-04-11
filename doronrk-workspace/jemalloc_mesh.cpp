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

	// begin mesh
	




	// end mesh
	
	free(mem1a);
	free(mem2b);
}
/*

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


	for (int i = 0; i < 11; i++) {
		free(ptrs[11 - 1 - i]);
	}
	doronrk_mesh();
}
*/
void allocate_some() {
	void *ptrs[100];
	for (int i = 0; i < 100; i++) {
		ptrs[i] = malloc(2048);
		//std::cout << "ptrs[ " << i << "]: " << ptrs[i] << std::endl;
		int *dst = (int*)ptrs[i];
		dst[0] = i;
	}
	for (int i = 0; i < 50; i++) {
		free(ptrs[i * 2 + i % 2]);
		//std::cout << "Freeing: " << ptrs[i * 2 + i % 2] << std::endl;
	}
	for (int i = 0; i < 50; i++) {
		int index = i * 2 + ((i + 1) % 2);
		int *dst = (int*)ptrs[index];
		assert(dst[0] == index);	
	}
	//mesh();
	for (int i = 0; i < 50; i++) {
		int index = i * 2 + ((i + 1) % 2);
		int *dst = (int*)ptrs[index];
		assert(dst[0] == index);	
	}
	for (int i = 49; i >= 0; i--) {
		free(ptrs[i * 2 + ((i + 1) % 2)]);
	}
}
int main(int argc, char** argv) {
	mesh_all_arenas();
	std::cout << "ran the program" << std::endl;
	return 0;
}
