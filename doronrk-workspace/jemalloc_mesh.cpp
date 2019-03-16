#include <iostream>
#include <jemalloc/jemalloc.h>
#include <cstdlib>

int main(int argc, char** argv) {
	void* mem = malloc(4096);
	free(mem);
	std::cout << "ran the program" << std::endl;
	return 0;

}
