#ifndef CRYPTUTILS_H
#define CRYPTUTILS_H
int encrypt(unsigned char encrypted[],
            const unsigned char precomputation[],
            const unsigned char nonce[],
            const unsigned char plain[], int length);
#endif /* end of include guard: CRYPTUTILS_H */
