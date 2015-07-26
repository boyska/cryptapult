#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <argp.h>
#include "fileutils.h"
#include "cryptutils.h"
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





void usage(char* progname) {
	printf("Usage: %s COUNT FILENAME\n", progname);
	printf("If COUNT > 0, %s will run in benchmark mode: only benchmark results will be printed\n", progname);
}

struct parameters {
	short int benchmark, check_tty;
	int benchmark_count;
	char *filename;
};

error_t parse_opt(int key, char* arg, struct argp_state *state) {
	struct parameters *opts = state->input;
	switch(key) {
		case 'b':
			opts->benchmark = 1;
			if(!sscanf(arg, "%d", &opts->benchmark_count)) {
				argp_failure(state, 2, 0,
					"'%s' is not a valid integer", arg);
			}
			if(opts->benchmark_count < 1) {
				argp_failure(state, 2, 0,
					"-b must be >= 1, got %d instead",
					opts->benchmark_count);
			}
			break;
		case 200:
			opts->check_tty = 0;
			break;
		case ARGP_KEY_ARG:
			if(state->arg_num > 1)
				argp_usage(state);
			opts->filename = arg;
			break;
		case ARGP_KEY_END:
			if(state->arg_num < 1)
				argp_usage(state);
			break;
		default:
			return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

int main(int argc, char **argv)
{
    unsigned char *c;
    unsigned char *plain = NULL;
    long plain_len;
    struct parameters params;
    params.benchmark = 0;
    params.benchmark_count = 1;
    params.check_tty = 1;

    struct argp_option options[] = {
	    {"bench", 'b', "COUNT", 0,
		    "Run encryption COUNT times and output benchmarks", 0},
	    {"ignore-tty", 200, 0, 0,
		    "Output encrypted text even on tty", 0},
	    {0}
    };
    struct argp argp = {options, parse_opt, "FILENAME",
	    "Encrypt file asymmetrically with the power of NaCl",
	    NULL, NULL, NULL};
    argp_parse(&argp, argc, argv, 0, 0, &params);

    plain_len = file_readwhole(params.filename, &plain);
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
    if(params.benchmark) {
	    fprintf(stderr, "Time of precomputation: %ld\n",
			    (time(NULL) - starttime));
    }
    if(!params.benchmark) {
	    if(params.check_tty && isatty(fileno(stdout))) {
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
	    for(int i=0; i < params.benchmark_count; i++) {
		    encrypt(c, precomputation, nonce, plain, plain_len);
	    }
	    fprintf(stderr, "Time per cycle: %.3f\n",
			    (double)(time(NULL) - starttime) / params.benchmark_count);
    }
    free(c);
    free(plain);
    return 0;
}
