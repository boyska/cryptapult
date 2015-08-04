#define _POSIX_C_SOURCE 199309L
#include <stdio.h>
#include <time.h>
#include <getopt.h>

#include <sodium.h>

#ifdef CLOCK_PROCESS_CPUTIME_ID
/* cpu time in the current process */
#define CLOCKTYPE  CLOCK_PROCESS_CPUTIME_ID
#else
/* this one should be appropriate to avoid errors on multiprocessors systems */
#define CLOCKTYPE  CLOCK_MONOTONIC
#endif

double time_it(void (*action) (void), int ntries)
{
    struct timespec tsi, tsf;

    clock_gettime(CLOCKTYPE, &tsi);
    for (int i = 0; i < ntries; i++) {
        action();
    }
    clock_gettime(CLOCKTYPE, &tsf);

    double elaps_s = difftime(tsf.tv_sec, tsi.tv_sec);
    unsigned long elaps_ns = tsf.tv_nsec - tsi.tv_nsec;

    return (elaps_s + (((double) elaps_ns) / 1.0e9)) / ntries;
}

void keygen()
{
    unsigned char pk[crypto_box_PUBLICKEYBYTES];
    unsigned char sk[crypto_box_SECRETKEYBYTES];
    crypto_box_keypair(pk, sk);
}

struct parameters {
    int benchmark_count;
};

void print_usage(FILE * stream, int exit_code, char *prog)
{
    fprintf(stream, "Usage: %s [options] FILENAME\n", prog);
    fprintf(stream, "Options:\n");
    fprintf(stream, "  -h, --help        Show this help\n");
    fprintf(stream,
            "  --runs COUNT     Run the encryption COUNT [default:100]\n");
    exit(exit_code);
}

int parse_opt(int argc, char **argv, struct parameters *opts)
{
    int option_index;
    int c;
    struct option long_options[] = {
        {"help", no_argument, NULL, 'h'},
        {"runs", required_argument, NULL, 'r'},
        {NULL, 0, NULL, 0}
    };
    char *program_name = argv[0];
    while (1) {
        option_index = 0;
        c = getopt_long(argc, argv, "hr:", long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'r':
            if (!sscanf(optarg, "%d", &opts->benchmark_count)) {
                fprintf(stderr, "'%s' is not a valid integer\n", optarg);
                return 2;
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
    if (argc - optind != 0) {
        fprintf(stderr, "Wrong number of arguments\n");
        return 2;
    }
    return 0;
}

int main(int argc, char **argv)
{
    if (sodium_init() == -1) {
        return 11;
    }
    struct parameters params;
    params.benchmark_count = 100;

    int parse_ret = parse_opt(argc, argv, &params);
    if (parse_ret) {
        print_usage(stderr, parse_ret, argv[0]);
    }
    printf("keygen: %lf\n", time_it(keygen, params.benchmark_count));
    return 0;
}

/* vim: set ts=4 sw=4 et: */
