#ifndef KEYFILES_H
#define KEYFILES_H

int keygen(char *pk_fname, char *sk_fname);
int pk_read(char *fname, unsigned char *pk);
int sk_read(char *fname, unsigned char *sk);

#endif /* end of include guard: KEYFILES_H */
