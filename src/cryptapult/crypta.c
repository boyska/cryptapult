#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <getopt.h>
#include "fileutils.h"
#include "cryptutils.h"
#include <sodium.h>

unsigned char pk[32] = {
 0xde,0x9e,0xdb,0x7d,0x7b,0x7d,0xc1,0xb4
,0xd3,0x5b,0x61,0xc2,0xec,0xe4,0x35,0x37
,0x3f,0x83,0x43,0xc8,0x5b,0x78,0x67,0x4d
,0xad,0xfc,0x7e,0x14,0x6f,0x88,0x2b,0x4f
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

void print_usage(FILE* stream, int exit_code, char* prog) {
	fprintf(stream, "Usage: %s [options] FILENAME\n", prog);
	fprintf(stream, "Options:\n");
	fprintf(stream, "  -h, --help        Show this help\n");
	fprintf(stream, "  --bench COUNT     Run the encryption COUNT times and\n"
			        "                    print only benchmarks to stdout\n");
	fprintf(stream, "  --ignore-tty      Output ciphertext even if stdout is a tty\n");
	exit(exit_code);
}

int parse_opt(int argc, char** argv, struct parameters *opts) {
	int option_index;
	int c;
	struct option long_options[] = {
		{"help", no_argument, NULL, 'h'},
		{"bench", required_argument, NULL, 0},
		{"ignore-tty", no_argument, NULL, 0},
		{NULL,0,NULL,0}
	};
	char *program_name = argv[0];
	while(1) {
		option_index = 0;
		c = getopt_long(argc, argv, "h", long_options, &option_index);
		if(c == -1)
			break;

		switch(c) {
			case 'T':
				opts->check_tty = 0;
				break;
			case 0: /* long option without a short arg */
				if(strcmp("bench", long_options[option_index].name) == 0) {
					opts->benchmark = 1;
					if(!sscanf(optarg, "%d", &opts->benchmark_count)) {
						fprintf(stderr, "'%s' is not a valid integer\n", optarg);
						return 2;
					}
					if(opts->benchmark_count < 1) {
						fprintf(stderr, "-b must be >= 1, got %d instead\n",
								opts->benchmark_count);
						return 2;
					}
				}
				if(strcmp("ignore-tty", long_options[option_index].name) == 0) {
					opts->check_tty = 0;
				}
				break;
			case 'h':
				print_usage(stdout, 0, program_name);
				break;
			case '?':
				break;
			default:
				break;
		}
	}
	if(argc - optind != 1) {
		fprintf(stderr, "Wrong number of arguments\n");
		return 2;
	}
	if(optind < argc) {
		int argnumber = 0;
		while(optind + argnumber < argc) {
			switch(argnumber) {
				case 0:
					opts->filename = argv[optind + argnumber++];
					break;
			}
		}
	}
	return 0;
}

int main(int argc, char **argv)
{
	if(sodium_init() == -1) {
        return 11;
    }
    unsigned char *c;
    unsigned char *plain = NULL;
    long plain_len;
    struct parameters params;
    params.benchmark = 0;
    params.benchmark_count = 1;
    params.check_tty = 1;

	int parse_ret = parse_opt(argc, argv, &params);
	if(parse_ret) {
		print_usage(stderr, parse_ret, argv[0]);
	}

    plain_len = file_readwhole(params.filename, &plain);
    if(plain_len < 0 || !plain) {
	    if(plain) {
		    sodium_free(plain);
	    }
	    fprintf(stderr, "Error reading file\n");
	    return 1;
    }

    c = calloc(plain_len + crypto_box_SEALBYTES, sizeof(char));
    sodium_memzero(c, plain_len + crypto_box_SEALBYTES);
    if(!params.benchmark) {
	    if(params.check_tty && isatty(fileno(stdout))) {
		    fprintf(stderr, "Output is a tty, refusing to write\n");
		    free(c);
		    sodium_free(plain);
		    return 10;
	    }
	    const int r = crypto_box_seal(c, plain, plain_len, pk);
	    if(r != 0) {
		    fprintf(stderr, "Error %d occured\n", r);
		    return 1;
	    }
	    fwrite(c, sizeof(unsigned char), plain_len + crypto_box_SEALBYTES , stdout);
    } else {
	    time_t starttime = time(NULL);
	    for(int i=0; i < params.benchmark_count; i++) {
		    crypto_box_seal(c, plain, plain_len, pk);
	    }
	    fprintf(stderr, "Time per cycle: %.3f\n",
			    (double)(time(NULL) - starttime) / params.benchmark_count);
    }
    free(c);
    sodium_free(plain);
    return 0;
}
