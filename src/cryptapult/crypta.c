#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <getopt.h>
#include "fileutils.h"

#include <sodium.h>

#include "cryptutils.h"
#include "keyfiles.h"


int fileno(FILE*);





struct parameters {
	short int benchmark, check_tty;
	int benchmark_count;
	char *filename;
	char *pk_fname;
};

void print_usage(FILE* stream, int exit_code, char* prog) {
	fprintf(stream, "Usage: %s [options] FILENAME PUBLICKEY\n", prog);
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
	if(argc - optind != 2) {
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
				case 1:
					opts->pk_fname = argv[optind + argnumber++];
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
	params.pk_fname = NULL;

	int parse_ret = parse_opt(argc, argv, &params);
	if(parse_ret) {
		print_usage(stderr, parse_ret, argv[0]);
	}
	unsigned char pk[crypto_box_PUBLICKEYBYTES];
	if(pk_read(params.pk_fname, pk)) {
		fprintf(stderr, "Error reading public key\n");
		return 1;
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
