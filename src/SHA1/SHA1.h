#ifndef BUFFER_SIZE
	#define BUFFER_SIZE 6400
#endif

#ifndef SHA1_H
#define SHA1_H

	#include <stdio.h>
	#include <stdint.h> /* C99 standard */

	enum SHA1_RESULT {
		ERROR_OPENING_FILE = 2,
		NULL_INPUT         = 1,
		NO_ERROR           = 0
	};

	/* Check if it is a C++ compiler */
	#ifdef __cplusplus
		extern "C" {
	#endif

		int SHA1_File(const char* filename, unsigned char result[20]);

	#ifdef __cplusplus
		}
	#endif

#endif
