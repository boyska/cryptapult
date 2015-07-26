#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
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
unsigned char* readwholefile(char* filename);

void randombytes(unsigned char buffer[], unsigned long long size)
{
	
	int fd;

	fd = open( "/dev/urandom", O_RDONLY );
	if( fd < 0 ) {
		fprintf( stderr, "Failed to open /dev/urandom\n" );
		exit(1);
	}

	int rc;
	if( (rc = read( fd, buffer, size )) >= 0 ) {
		close( fd );
	}
}

char *to_hex( char hex[], const unsigned char bin[], size_t length )
{
	unsigned char *p0 = (unsigned char *)bin;
	char *p1 = hex;

	for(size_t i = 0; i < length; i++ ) {
		sprintf( p1, "%02x", *p0 );
		p0 += 1;
		p1 += 2;
	}

	return hex;
}

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

#define MAX_MSG_SIZE 102400

int encrypt(unsigned char encrypted[], const unsigned char pk[],
		const unsigned char sk[], const unsigned char nonce[],
		const unsigned char plain[], int length) {
	
	unsigned char *temp_plain = malloc(MAX_MSG_SIZE);
	unsigned char *temp_encrypted = malloc(MAX_MSG_SIZE);
	int rc;

	if(length+crypto_box_ZEROBYTES >= MAX_MSG_SIZE) {
		return -2;
	}

	memset(temp_plain, '\0', crypto_box_ZEROBYTES);
	memcpy(temp_plain + crypto_box_ZEROBYTES, plain, length);

	rc = crypto_box(temp_encrypted, temp_plain, crypto_box_ZEROBYTES + length, nonce, pk, sk);

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

unsigned char* readwholefile(char* filename) {
	unsigned char *content;
	long fsize;
	FILE *f = fopen(filename, "rb");
	if(f == NULL) {
		fprintf(stderr, "Failure reading '%s' (non existent file?)\n",
				filename);
		return NULL;
	}
	fseek(f, 0, SEEK_END);
	fsize = ftell(f);
	fseek(f, 0, SEEK_SET);

	content = malloc(fsize + 1);
	if(content == NULL) {
		fprintf(stderr, "Failure reading '%s' (not enough memory?)\n",
				filename);
		return NULL;
	}
	fread(content, fsize, sizeof(char), f);
	fclose(f);

	content[fsize] = 0;
	return content;
}

int main(int ac, char **av)
{
    unsigned char c[MAX_MSG_SIZE];
    int r;
    int count, i;
    unsigned char *plain;
    size_t plain_len;

    time_t starttime;

    if(ac != 3) {
	    usage(av[0]);
	    return 2;
    }
    sscanf(av[1], "%d", &count);
    plain = readwholefile(av[2]);
    if(!plain) {
	    return 1;
    }
    plain_len = strlen((char*)plain);

    memset(c, '\0', MAX_MSG_SIZE);
    if(count == 0) {
	    r = encrypt(c, pk, sk, nonce, plain, plain_len);
	    fwrite(c, r, sizeof *c, stdout);
    } else {
	    starttime = time(NULL);
	    for(i=0; i < count; i++) {
		    encrypt(c, pk, sk, nonce, plain, plain_len);
	    }
	    fprintf(stderr, "Time per cycle: %.3f\n",
			    (double)(time(NULL) - starttime) / count);
    }
    free(plain);
    return 0;
}