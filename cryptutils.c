#include <string.h>
#include <stdlib.h>
#include <sodium.h>

static int is_zero( const unsigned char *data, int len )
{
	int i;
	int rc;

	rc = 0;
	for(i = 0; i < len; ++i) {
		rc |= data[i];
	}

	return rc;
}

int encrypt(unsigned char encrypted[],
		const unsigned char precomputation[],
		const unsigned char nonce[],
		const unsigned char plain[], int length) {
	
	unsigned char *temp_plain = malloc(length + crypto_box_ZEROBYTES + crypto_box_BOXZEROBYTES + 1);
	if(!temp_plain) {
		return -2;
	}
	memset(temp_plain, '\0', crypto_box_ZEROBYTES);
	memcpy(temp_plain + crypto_box_ZEROBYTES, plain, length);

	unsigned char *temp_encrypted = malloc(length + crypto_box_ZEROBYTES + crypto_box_BOXZEROBYTES + 1);
	if(!temp_encrypted) {
		return -2;
	}
	int rc;

	rc = crypto_box_afternm(temp_encrypted, temp_plain,
			crypto_box_ZEROBYTES + length, nonce,
			precomputation);

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
