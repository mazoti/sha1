#include <stdio.h>

#include "SHA1/SHA1.h"

int main(int argc, char* argv[]){

	int i;
	unsigned char sha1_final[20];

	if(argc < 2){
		fprintf(stderr, "\nUsage: sha1 <file1> <file2> <fileN>...\n");
		return 1;
	}

	for(i = 1; i < argc; ++i){
		switch(SHA1_File(argv[i], sha1_final)){
			case NO_ERROR:
				break;
			case NULL_INPUT:
				fprintf(stderr, "Input filename is NULL\n");
				continue;
			case ERROR_OPENING_FILE:
				fprintf(stderr, "Can't open or read file \"%s\"\n", argv[i]);
				continue;
			default:
				fprintf(stderr, "Can't close the file \"%s\"\n", argv[i]);
				continue;
		}

		printf("%s => %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n", argv[i],
			sha1_final[0], sha1_final[1], sha1_final[2], sha1_final[3], sha1_final[4], sha1_final[5], sha1_final[6],
			sha1_final[7], sha1_final[8], sha1_final[9], sha1_final[10],sha1_final[11],sha1_final[12],sha1_final[13],
			sha1_final[14],sha1_final[15],sha1_final[16],sha1_final[17],sha1_final[18],sha1_final[19]);
	}

	return 0;

}
