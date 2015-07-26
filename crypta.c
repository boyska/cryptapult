#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include "fileutils.h"
#include "tweetnacl.h"

unsigned char sk[32] = {
 0x77,0x07,0x6d,0x0a,0x73,0x18,0xa5,0x7d
,0x3c,0x16,0xc1,0x72,0x51,0xb2,0x66,0x45
,0xdf,0x4c,0x2f,0x87,0xeb,0xc0,0x99,0x2a
,0xb1,0x77,0xfb,0xa5,0x1d,0xb9,0x2c,0x2a
} ;

unsigned char pk[32] = {
 0xde,0x9e,0xdb,0x7d,0x7b,0x7d,0xc1,0xb4
,0xd3,0x5b,0x61,0xc2,0xec,0xe4,0x35,0x37
,0x3f,0x83,0x43,0xc8,0x5b,0x78,0x67,0x4d
,0xad,0xfc,0x7e,0x14,0x6f,0x88,0x2b,0x4f
} ;

unsigned char nonce[24] = {
 0x69,0x69,0x6e,0xe9,0x55,0xb6,0x2b,0x73
,0xcd,0x62,0xbd,0xa8,0x75,0xfc,0x73,0xd6
,0x82,0x19,0xe0,0x03,0x6b,0x7a,0x0b,0x37
} ;
int fileno(FILE*);


int is_zero( const unsigned char *data, int len )
{
	int i;
	int rc;

	rc = 0;
	for(i = 0; i < len; ++i) {
		rc |= data[i];
	}

	return rc;
}

int encrypt(unsigned char encrypted[],
		const unsigned char precomputation[],
		const unsigned char nonce[],
		const unsigned char plain[], int length) {
	
	unsigned char *temp_plain = malloc(length + crypto_box_ZEROBYTES + crypto_box_BOXZEROBYTES + 1);
	if(!temp_plain) {
		return -2;
	}
	memset(temp_plain, '\0', crypto_box_ZEROBYTES);
	memcpy(temp_plain + crypto_box_ZEROBYTES, plain, length);

	unsigned char *temp_encrypted = malloc(length + crypto_box_ZEROBYTES + crypto_box_BOXZEROBYTES + 1);
	if(!temp_encrypted) {
		return -2;
	}
	int rc;

	rc = crypto_box_afternm(temp_encrypted, temp_plain,
			crypto_box_ZEROBYTES + length, nonce,
			precomputation);

	if( rc != 0 ) {
		free(temp_plain);
		free(temp_encrypted);
		return -1;
	}

	if( is_zero(temp_plain, crypto_box_BOXZEROBYTES) != 0 ) {
		free(temp_plain);
		free(temp_encrypted);
		return -3;
	}

	free(temp_plain);

	memcpy(encrypted, temp_encrypted + crypto_box_BOXZEROBYTES, crypto_box_ZEROBYTES + length);
	free(temp_encrypted);

	return crypto_box_ZEROBYTES + length - crypto_box_BOXZEROBYTES;
}


void usage(char* progname) {
	printf("Usage: %s COUNT FILENAME\n", progname);
	printf("If COUNT > 0, %s will run in benchmark mode: only benchmark results will be printed\n", progname);
}

int main(int argc, char **argv)
{
    unsigned char *c;
    int count;
    unsigned char *plain = NULL;
    long plain_len;


    if(argc != 3) {
	    usage(argv[0]);
	    return 2;
    }
    if(!sscanf(argv[1], "%d", &count)) {
	    usage(argv[0]);
	    return 2;
    }
    sscanf(argv[1], "%d", &count);
    plain_len = file_readwhole(argv[2], &plain);
    if(plain_len < 0 || !plain) {
	    if(plain) {
		    free(plain);
	    }
	    fprintf(stderr, "Error reading file\n");
	    return 1;
    }

    c = malloc(plain_len + crypto_box_ZEROBYTES + crypto_box_BOXZEROBYTES + 1);
    memset(c, '\0', plain_len);
    unsigned char precomputation[crypto_box_BEFORENMBYTES];
    time_t starttime = time(NULL);
    crypto_box_beforenm(precomputation, pk, sk);
    if(count > 0) {
	    fprintf(stderr, "Time of precomputation: %ld\n",
			    (time(NULL) - starttime));
    }
    if(count == 0) {
	    if(isatty(fileno(stdout))) {
		    fprintf(stderr, "Output is a tty, refusing to write\n");
		    free(plain);
		    return 10;
	    }
	    const int r = encrypt(c, precomputation, nonce, plain, plain_len);
	    if(r < 0) {
		    fprintf(stderr, "Error %d occured\n", r);
		    return 1;
	    }
	    fwrite(c, sizeof(unsigned char), r, stdout);
    } else {
	    starttime = time(NULL);
	    for(int i=0; i < count; i++) {
		    encrypt(c, precomputation, nonce, plain, plain_len);
	    }
	    fprintf(stderr, "Time per cycle: %.3f\n",
			    (double)(time(NULL) - starttime) / count);
    }
    free(c);
    free(plain);
    return 0;
}
