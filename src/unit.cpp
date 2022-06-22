#include <iostream>
#include <fstream>

#include <cstdint>
#include <cassert>

#include <chrono>
#include <ctime>

#include "SHA1/SHA1.h"

using namespace std;

int main(){

	unsigned char result[20];
	chrono::time_point<chrono::system_clock> start = chrono::system_clock::now();

	// Test an invalid file
	cout << endl << " => Testing inexistent file... ";
	assert(SHA1_File(NULL , result) == 1);
	cout << "passed" << endl << " => Testing \"abc\" file........ ";

	// Create a file for test
	ofstream abc_file("abc.txt", ios::out | ios::trunc);
	assert(abc_file.is_open());
	abc_file << "abc";
	abc_file.close();

	// Verify the SHA1 of this file: must be a9993e364706816aba3e25717850c26c9cd0d89d
	assert(!SHA1_File("abc.txt", result));
	assert(result[0] == 0xA9);
	assert(result[1] == 0x99);
	assert(result[2] == 0x3E);
	assert(result[3] == 0x36);
	assert(result[4] == 0x47);
	assert(result[5] == 0x06);
	assert(result[6] == 0x81);
	assert(result[7] == 0x6A);
	assert(result[8] == 0xBA);
	assert(result[9] == 0x3E);
	assert(result[10] == 0x25);
	assert(result[11] == 0x71);
	assert(result[12] == 0x78);
	assert(result[13] == 0x50);
	assert(result[14] == 0xC2);
	assert(result[15] == 0x6C);
	assert(result[16] == 0x9C);
	assert(result[17] == 0xD0);
	assert(result[18] == 0xD8);
	assert(result[19] == 0x9D);

	cout << "passed" << endl << " => Testing a 5GB file........ ";

	// Create a 1GB file for test
	ofstream huge_file("huge.txt" , ios::out | ios::trunc);
	assert(huge_file.is_open());
	for(uint64_t i = 0; i < 1024 * 1024 * 1024; ++i) huge_file << "abcde";
	huge_file.close();

	// Verify the SHA1 of this file: must be 1e1db074c4deab2cc4d7141b8ba83cb7ba30c49e
	assert(!SHA1_File("huge.txt", result));
	assert(result[0] == 0x1E);
	assert(result[1] == 0x1D);
	assert(result[2] == 0xB0);
	assert(result[3] == 0x74);
	assert(result[4] == 0xC4);
	assert(result[5] == 0xDE);
	assert(result[6] == 0xAB);
	assert(result[7] == 0x2C);
	assert(result[8] == 0xC4);
	assert(result[9] == 0xD7);
	assert(result[10] == 0x14);
	assert(result[11] == 0x1B);
	assert(result[12] == 0x8B);
	assert(result[13] == 0xA8);
	assert(result[14] == 0x3C);
	assert(result[15] == 0xB7);
	assert(result[16] == 0xBA);
	assert(result[17] == 0x30);
	assert(result[18] == 0xC4);
	assert(result[19] == 0x9E);

	cout << "passed" << endl << endl << " *** ALL TESTS PASSED ***" << endl;

	cout << endl << "Time elapsed: "
		<< chrono::duration_cast <chrono::seconds>(chrono::system_clock::now() - start).count()
		<< " second(s)" << endl;

	return 0;
}
