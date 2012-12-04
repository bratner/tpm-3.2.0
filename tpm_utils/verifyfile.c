/*
 * libtpm: sign test program
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
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

int main(int argc, char *argv[])
{
	int ret;
	struct stat sbuf;
	unsigned char databuff[65535];	/* data read work buffer */
	unsigned char datahash[20];	/* hash of data file */
	unsigned char sig[4096];	/* signature */
	unsigned int siglen;	/* signature length */
	SHA_CTX sha;
	FILE *datafile;
	FILE *sigfile;
	FILE *keyfile;
	EVP_PKEY *pkey;
	RSA *rsa;

	if (argc < 4) {
		fprintf(stderr,
			"Usage: verifyfile <sig file> "
			"<data file> <pubkey file>\n");
		exit(1);
	}
	/*
	 ** read and hash the data file
	 */
	datafile = fopen(argv[2], "r");
	if (datafile == NULL) {
		fprintf(stderr, "Unable to open data file '%s'\n",
			argv[2]);
		exit(2);
	}
	SHA1_Init(&sha);
	for (;;) {
		ret = fread(databuff, 1, sizeof databuff, datafile);
		if (ret < 0) {
			fprintf(stderr,
				"I/O Error while reading data file '%s'\n",
				argv[2]);
			exit(3);
		}
		SHA1_Update(&sha, databuff, ret);
		if (ret < sizeof databuff)
			break;
	}
	fclose(datafile);
	SHA1_Final(datahash, &sha);
	/*
	 ** get size of signature file
	 */
	stat(argv[1], &sbuf);
	siglen = (int) sbuf.st_size;
	sigfile = fopen(argv[1], "r");
	if (sigfile == NULL) {
		fprintf(stderr, "Unable to open signature file '%s'\n",
			argv[1]);
		exit(4);
	}
	/*
	 ** read the signature file
	 */
	ret = fread(sig, 1, siglen, sigfile);
	if (ret != siglen) {
		fprintf(stderr,
			"I/O Error while reading signature file '%s'\n",
			argv[1]);
		exit(5);
	}
	fclose(sigfile);
	/*
	 ** read the key file
	 */
	keyfile = fopen(argv[3], "r");
	if (keyfile == NULL) {
		fprintf(stderr, "Unable to open public key file '%s'\n",
			argv[3]);
		exit(6);
	}
	pkey = PEM_read_PUBKEY(keyfile, NULL, NULL, NULL);
	if (pkey == NULL) {
		fprintf(stderr,
			"I/O Error while reading public key file '%s'\n",
			argv[3]);
		exit(7);
	}
	rsa = EVP_PKEY_get1_RSA(pkey);
	if (rsa == NULL) {
		fprintf(stderr, "Error while converting public key \n");
		exit(8);
	}
	ret = RSA_verify(NID_sha1, datahash, 20, sig, siglen, rsa);
	if (ret != 1) {
		fprintf(stderr, "Verification Failed\n");
		exit(100);
	}
	RSA_free(rsa);
	EVP_PKEY_free(pkey);
	exit(0);
}
