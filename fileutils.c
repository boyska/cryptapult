#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

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

long file_readwhole(char* filename, unsigned char **buf) {
	unsigned char *content;
	long fsize;
	FILE *f = fopen(filename, "rb");
	if(f == NULL) {
		fprintf(stderr, "Failure reading '%s' (non existent file?)\n",
				filename);
		return -1;
	}
	fseek(f, 0, SEEK_END);
	fsize = ftell(f);
	fseek(f, 0, SEEK_SET);

	content = malloc(fsize + 1);
	if(content == NULL) {
		fprintf(stderr, "Failure reading '%s' (not enough memory?)\n",
				filename);
		return -2;
	}
	fread(content, fsize, sizeof(char), f);
	fclose(f);

	content[fsize] = 0;
	*buf = content;
	return fsize;
}


