#include <stdio.h>
#include <unistd.h>
#include <getopt.h>

#include <sodium.h>

struct parameters {
	short int overwrite;
	char *pk_fname;
	char *sk_fname;
};

void print_usage(FILE* stream, int exit_code, char* prog) {
	fprintf(stream, "Usage: %s [options] PUBLIC_KEYFILE SECRET_KEYFILE\n",
			prog);
	fprintf(stream, "Options:\n");
	fprintf(stream, "  -h, --help        Show this help\n");
	fprintf(stream, "  --overwrite       Allow overwriting keyfiles\n");
	exit(exit_code);
}


int parse_opt(int argc, char** argv, struct parameters *opts) {
	int option_index;
	int c;
	struct option long_options[] = {
		{"help", no_argument, NULL, 'h'},
		{"overwrite", no_argument, NULL, 'w'},
		{NULL,0,NULL,0}
	};
	char *program_name = argv[0];
	while(1) {
		option_index = 0;
		c = getopt_long(argc, argv, "h:w", long_options, &option_index);
		if(c == -1)
			break;

		switch(c) {
			case 'h':
				print_usage(stdout, 0, program_name);
				break;
			case 'w':
				opts->overwrite = 1;
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
	opts->pk_fname = argv[optind];
	opts->sk_fname = argv[optind + 1];
	return 0;
}

int keygen(char* pk_fname, char* sk_fname)
{
	unsigned char pk[crypto_box_PUBLICKEYBYTES];
	unsigned char sk[crypto_box_SECRETKEYBYTES];
	crypto_box_keypair(pk, sk);
	FILE* buf;
	buf = fopen(pk_fname, "w");
	if(buf == NULL) {
		return 1;
	}
	if(fwrite(pk, sizeof(unsigned char), crypto_box_PUBLICKEYBYTES, buf)
			!= crypto_box_PUBLICKEYBYTES) {
		fclose(buf);
		unlink(pk_fname);
		return 2;
	}
	fclose(buf);

	buf = fopen(sk_fname, "w");
	if(buf == NULL) {
		return 1;
	}
	if(fwrite(sk, sizeof(unsigned char), crypto_box_SECRETKEYBYTES, buf)
			!= crypto_box_SECRETKEYBYTES) {
		fclose(buf);
		unlink(pk_fname);
		unlink(sk_fname);
		return 2;
	}
	fclose(buf);
	return 0;
}

int main(int argc, char **argv)
{
	struct parameters params;
	int gen_ret;
	if(sodium_init() == -1) {
		return 11;
	}
	params.overwrite = 0;
	params.pk_fname = NULL;
	params.sk_fname = NULL;

	int parse_ret = parse_opt(argc, argv, &params);
	if(parse_ret) {
		print_usage(stderr, parse_ret, argv[0]);
	}
	if(!params.overwrite) {
		if(!access(params.pk_fname, F_OK)) {
			fprintf(stderr, "File already exists (%s)\n", params.pk_fname);
			return 1;
		}
		if(!access(params.sk_fname, F_OK)) {
			fprintf(stderr, "File already exists (%s)\n", params.sk_fname);
			return 1;
		}
	}
	gen_ret = keygen(params.pk_fname, params.sk_fname);
	return gen_ret;
}

