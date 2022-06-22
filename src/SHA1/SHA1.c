#include "SHA1.h"

#if BUFFER_SIZE <= 0
	#error BUFFER_SIZE must be greater than 0
#elif BUFFER_SIZE & 63 != 0
	#error BUFFER_SIZE must be divisible by 64
#endif

#define EXTENDED(i)                                                                                    \
		extended[i] = (extended[(i-3)] ^ extended[(i-8)] ^ extended[(i-14)] ^ extended[(i-16)]);       \
		extended[i] = ((extended[i] >> 31) | (extended[i] << 1));                                      \

#define PART1(i)                                                                                       \
		extended[i] = (data[(i << 2)] << 24) + (data[(i << 2) +1] << 16)                               \
					+ (data[(i << 2) + 2] << 8) + (data[( i << 2) + 3]);                               \
		temp = ((A >> 27) | (A << 5)) + ((B & C) | ((~B) & D)) + E + extended[i] + 0x5A827999;         \
		E = D; D = C; C = ((B >> 2) | (B << 30)); B = A; A = temp;                                     \

#define PART2(i)                                                                                       \
		EXTENDED(i);                                                                                   \
		temp = ((A >> 27) | (A << 5)) + ((B & C) | ((~B) & D)) + E + extended[i] + 0x5A827999;         \
		E = D; D = C; C = (( B >> 2) | (B << 30)); B = A; A = temp;                                    \

#define PART3(i)                                                                                       \
		EXTENDED(i);                                                                                   \
		temp = ((A >> 27) | (A << 5)) + (B ^ C ^ D) + E + extended[i] + 0x6ED9EBA1;                    \
		E = D; D = C; C = ((B >> 2) | (B << 30)); B = A; A = temp;                                     \

#define PART4(i)                                                                                       \
		EXTENDED(i);                                                                                   \
		temp = ((A >> 27) | (A << 5)) + ((B & C) | (B & D) | (C & D) ) + E + extended[i] + 0x8F1BBCDC; \
		E = D; D = C; C = (( B >> 2) | (B << 30)); B = A; A = temp;                                    \

#define PART5(i)                                                                                       \
		EXTENDED(i);                                                                                   \
		temp = ((A >> 27) | (A << 5)) + (B ^ C ^ D) + E + extended[i] + 0xCA62C1D6;                    \
		E = D; D = C; C = ((B >> 2) | (B << 30)); B = A; A = temp;                                     \

#define SHA1_DATA                                                                                      \
		A = h0; B = h1; C = h2; D = h3; E = h4;                                                        \
                                                                                                       \
		PART1(0);  PART1(1); PART1(2); PART1(3);  PART1(4);  PART1(5);  PART1(6);                      \
		PART1(7);  PART1(8); PART1(9); PART1(10); PART1(11); PART1(12); PART1(13);                     \
		PART1(14); PART1(15);                                                                          \
                                                                                                       \
		PART2(16); PART2(17); PART2(18); PART2(19);                                                    \
                                                                                                       \
		PART3(20); PART3(21); PART3(22); PART3(23); PART3(24); PART3(25); PART3(26);                   \
		PART3(27); PART3(28); PART3(29); PART3(30); PART3(31); PART3(32); PART3(33);                   \
		PART3(34); PART3(35); PART3(36); PART3(37); PART3(38); PART3(39);                              \
                                                                                                       \
		PART4(40); PART4(41); PART4(42); PART4(43); PART4(44); PART4(45); PART4(46);                   \
		PART4(47); PART4(48); PART4(49); PART4(50); PART4(51); PART4(52); PART4(53);                   \
		PART4(54); PART4(55); PART4(56); PART4(57); PART4(58); PART4(59);                              \
                                                                                                       \
		PART5(60); PART5(61); PART5(62); PART5(63); PART5(64); PART5(65); PART5(66);                   \
		PART5(67); PART5(68); PART5(69); PART5(70); PART5(71); PART5(72); PART5(73);                   \
		PART5(74); PART5(75); PART5(76); PART5(77); PART5(78); PART5(79);                              \
                                                                                                       \
		h0 += A; h1 += B; h2 += C; h3 += D; h4 += E;                                                   \

int SHA1_File(const char* filename, unsigned char result[20]){

	FILE *fp;
	unsigned char data[64], buffer[BUFFER_SIZE];

	size_t i, j, buffer_bytes;
	uint64_t size, bytes_read;
	uint32_t A, B, C, D, E, temp, h0, h1, h2, h3, h4, extended[80];

	if(filename == NULL) return NULL_INPUT;

	fp = fopen(filename, "rb");
	if(fp == NULL) return ERROR_OPENING_FILE;

	h0 = 0x67452301;
	h1 = 0xEFCDAB89;
	h2 = 0x98BADCFE;
	h3 = 0x10325476;
	h4 = 0xC3D2E1F0;

	size = 0;

	for(buffer_bytes = fread(buffer, sizeof(unsigned char), BUFFER_SIZE, fp);
		buffer_bytes == BUFFER_SIZE;
		buffer_bytes = fread(buffer, sizeof(unsigned char), BUFFER_SIZE, fp)){

		for(i = 0; i < BUFFER_SIZE; i += 64){
			for(j = 0; j < 64; ++j) data[j] = buffer[i + j];
			SHA1_DATA;
			size += 512;
		}
	}

	/* Whole file read */
	for(i = 0; i < (buffer_bytes >> 6); ++i){
		for(j = 0; j < 64; ++j) data[j] = buffer[(i << 6) + j];
		SHA1_DATA;
		size += 512;
	}

	bytes_read = buffer_bytes & 63;

	for(j = 0; j < bytes_read; ++j) data[j] = buffer[(i << 6) + j];

	/* Padding */
	data[bytes_read] = 0x80;
	if(bytes_read < 63){
		for(i = 0; i < (63 - bytes_read); ++i) data[bytes_read + 1 + i] = 0;
	}

	/* The padding needs another chunk */
	if(bytes_read > 55){
		SHA1_DATA;

		data[0]  = data[1]  = data[2]  = data[3]  = data[4]  = data[5]  = data[6]  = data[7]  =
		data[8]  = data[9]  = data[10] = data[11] = data[12] = data[13] = data[14] = data[15] =
		data[16] = data[17] = data[18] = data[19] = data[20] = data[21] = data[22] = data[23] =
		data[24] = data[25] = data[26] = data[27] = data[28] = data[29] = data[30] = data[31] =
		data[32] = data[33] = data[34] = data[35] = data[36] = data[37] = data[38] = data[39] =
		data[40] = data[41] = data[42] = data[43] = data[44] = data[45] = data[46] = data[47] =
		data[48] = data[49] = data[50] = data[51] = data[52] = data[53] = data[54] = data[55] =
		data[56] = data[57] = data[58] = data[59] = data[60] = data[61] = data[62] = data[63] = 0;
	}

	size += (bytes_read << 3);

	data[63] = (unsigned char)(size & 255 );
	data[62] = (unsigned char)((size >> 8) & 255);
	data[61] = (unsigned char)((size >> 16) & 255);
	data[60] = (unsigned char)((size >> 24) & 255);
	data[59] = (unsigned char)((size >> 32) & 255);
	data[58] = (unsigned char)((size >> 40) & 255);
	data[57] = (unsigned char)((size >> 48) & 255);
	data[56] = (unsigned char)((size >> 56) & 255);

	/* Calculates sha1 of the last chunk with padding */
	SHA1_DATA;

	/* Convert back */
	result[0] = (unsigned char)((h0 >> 24) & 255);
	result[1] = (unsigned char)((h0 >> 16) & 255);
	result[2] = (unsigned char)((h0 >>  8) & 255);
	result[3] = (unsigned char)(h0 & 255);
	result[4] = (unsigned char)((h1 >> 24) & 255);
	result[5] = (unsigned char)((h1 >> 16) & 255);
	result[6] = (unsigned char)((h1 >>  8) & 255);
	result[7] = (unsigned char)(h1 & 255);
	result[8] = (unsigned char)((h2 >> 24) & 255);
	result[9] = (unsigned char)((h2 >> 16) & 255);
	result[10] = (unsigned char)((h2 >>  8) & 255);
	result[11] = (unsigned char)(h2 & 255);
	result[12] = (unsigned char)((h3 >> 24) & 255);
	result[13] = (unsigned char)((h3 >> 16) & 255);
	result[14] = (unsigned char)((h3 >>  8) & 255);
	result[15] = (unsigned char)(h3 & 255);
	result[16] = (unsigned char)((h4 >> 24) & 255);
	result[17] = (unsigned char)((h4 >> 16) & 255);
	result[18] = (unsigned char)((h4 >> 8) & 255);
	result[19] = (unsigned char)(h4 & 255);

	return fclose(fp);
}
