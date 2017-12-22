#include <getopt.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>


extern int optind;
int main(int argc, char **argv){
	int option;
	char *keyFile;
	while ((option = getopt(argc, argv, "k?:")) != -1) {
	    switch (option) {
	    case 'k':
	        if(argv[optind] == NULL){
	        	printf("file name for storing key must be specified.");
	        	return 0;
	        }else{
	        	keyFile = argv[optind];
	        }
	        break;
	    case '?':
	        printf("keygen -k <keyfilename> generates a random key of size equal to block size for AES encryption and stores it in the file with the supplied name. ");
	    	return 1;
	    default:
	    	printf("type 'keygen ?' for help");
	    	return 1;
	    }
	}
	/* generate the key */
	unsigned char key[AES_BLOCK_SIZE];
	int success = RAND_bytes(key, AES_BLOCK_SIZE);
	if(!success){
		printf("Error in ganerating key.");
		exit(0);
	}
	FILE *keyFilePtr;
	keyFilePtr = fopen(keyFile, "wb");
	fwrite(key, AES_BLOCK_SIZE, 1, keyFilePtr);
	fclose(keyFilePtr);
	return 1;
}
