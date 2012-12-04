/*
 * libtpm: read endorsement key test program
 *
 * Copyright (C) 2004 IBM Corporation
 * Author: J. Kravitz
 *
 *      This program is free software; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 2 of the License, or
 *      (at your option) any later version.
 */

#include <stdio.h>
#include <string.h>
#include "tpmfunc.h"
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>

int main(int argc, char *argv[])
{
	int ret, i;
	unsigned char pass1hash[20];
	pubkeydata pubek;
	RSA *rsa;		/* OpenSSL format Public Key */
	FILE *keyfile;		/* output file for public key */
	EVP_PKEY pkey;		/* OpenSSL public key */

	TPM_setlog(0);		/* turn off verbose output */
	if (argc > 1) {		/* if password is specified, use OwnerReadKey */
		TSS_sha1(argv[1], strlen(argv[1]), pass1hash);
		ret = TPM_OwnerReadPubek(pass1hash, &pubek);
		if (ret != 0) {
			fprintf(stderr,
				"Error %s from TPM_OwnerReadPubek\n",
				TPM_GetErrMsg(ret));
			exit(2);
		}
	} else {		/* if no password specified, use ReadEKey */

		ret = TPM_ReadPubek(&pubek);
		if (ret != 0) {
			fprintf(stderr,
				"Error %s from TPM_ReadPubek:\n",
				TPM_GetErrMsg(ret));
			exit(2);
		}
	}
	/*
	 ** convert the returned public key to OpenSSL format and
	 ** export it to a file
	 */
	rsa = TSS_convpubkey(&pubek);
	if (rsa == NULL) {
		fprintf(stderr, "Error from TSS_convpubkey\n");
		exit(3);
	}
	OpenSSL_add_all_algorithms();
	EVP_PKEY_assign_RSA(&pkey, rsa);
	keyfile = fopen("pubek.pem", "w");
	if (keyfile == NULL) {
		fprintf(stderr, "Unable to create public key file\n");
		exit(4);
	}
	ret = PEM_write_PUBKEY(keyfile, &pkey);
	if (ret == 0) {
		fprintf(stderr, "Unable to write public key file\n");
		exit(5);
	}
	printf("pubek.pem successfully written\n");
	printf("Pubek keylength %d\nModulus:", pubek.keylength);
	for (i = 0; i < pubek.keylength; i++) {
		if (!(i % 16))
			printf("\n");
		printf("%02X ", pubek.modulus[i]);
	}
	printf("\n");

	fclose(keyfile);
	RSA_free(rsa);
	exit(0);
}
