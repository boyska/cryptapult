#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include <sodium.h>


/* Read a whole file in a securely-allocated read-only buffer
 * Returns the number of read bytes, if successful, or sth < 0 if not
 * */
long file_readwhole(char *filename, unsigned char **buf)
{
    unsigned char *content;
    long fsize;
    FILE *f = fopen(filename, "rb");
    if (f == NULL) {
        fprintf(stderr, "Failure reading '%s' (non existent file?)\n",
                filename);
        return -1;
    }
    if (fseek(f, 0, SEEK_END) != 0) {
        fprintf(stderr, "Failure reading '%s'\n", filename);
        return -1;
    }
    fsize = ftell(f);
    if (fsize == -1) {
        fprintf(stderr, "Failure reading '%s'\n", filename);
        return -1;
    }
    if (fseek(f, 0, SEEK_SET)) {
        fprintf(stderr, "Failure reading '%s'\n", filename);
        return -1;
    }

    content = sodium_allocarray(fsize, sizeof(char));
    if (content == NULL) {
        fprintf(stderr, "Failure reading '%s' (not enough memory?)\n",
                filename);
        return -2;
    }
    size_t rbytes = fread(content, sizeof(char), fsize, f);
    if (rbytes != (size_t) fsize) {
        fprintf(stderr,
                "Failure reading '%s' (%zu bytes read instead of %ld)\n",
                filename, rbytes, fsize);
        sodium_free(content);
        return -3;
    }
    fclose(f);

    sodium_mprotect_readonly(content);
    *buf = content;
    return fsize;
}

long file_mmapwhole(char* filename, char** buf) {
    int fd = open(filename, O_RDONLY);
    struct stat filestat;
    fstat(fd, &filestat);
    char* address = (char*) mmap(0, filestat.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    *buf = address;
    return filestat.st_size;
}

/* vim: set et ts=4 sw=4 */
