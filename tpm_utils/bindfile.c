/*
 * libtpm: bind/unbind test program
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
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <sys/types.h>
#include <pwd.h>
#include <sys/stat.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include "tpmfunc.h"

/**************************************************************************/
/*                                                                        */
/*  Main Program                                                          */
/*                                                                        */
/**************************************************************************/
int main(int argc, char *argv[])
{
	int i;
	int ret;
	RSA *rsa;
	EVP_PKEY *pkey;
	FILE *dfile;
	FILE *ofile;
	FILE *kfile;
	unsigned char blob[4096];
	unsigned int bloblen;
	unsigned int datlen;
	struct tcpa_bound_data {
		unsigned char version[4];
		unsigned char type;
		unsigned char data[256];
	} bound;
	struct stat sbuf;

	if (argc < 4) {
		fprintf(stderr,
			"Usage: bindfile <pubkey file> <data file> <output file>\n");
		exit(1);
	}
	TPM_setlog(0);
	/*
	 ** get size of data file
	 */
	stat(argv[2], &sbuf);
	datlen = (int) sbuf.st_size;
	/*
	 ** read the data file
	 */
	dfile = fopen(argv[2], "r");
	if (dfile == NULL) {
		fprintf(stderr, "Unable to open data file '%s'\n",
			argv[2]);
		exit(2);
	}
	memset(bound.data, 0, 256);
	ret = fread(bound.data, 1, datlen, dfile);
	fclose(dfile);
	if (ret != datlen) {
		fprintf(stderr, "Unable to read data file\n");
		exit(3);
	}
	/*
	 ** read the key file
	 */
	kfile = fopen(argv[1], "r");
	if (kfile == NULL) {
		fprintf(stderr, "Unable to open public key file '%s'\n",
			argv[1]);
		exit(4);
	}
	pkey = PEM_read_PUBKEY(kfile, NULL, NULL, NULL);
	fclose(kfile);
	if (pkey == NULL) {
		fprintf(stderr,
			"I/O Error while reading public key file '%s'\n",
			argv[1]);
		exit(5);
	}
	rsa = EVP_PKEY_get1_RSA(pkey);
	if (rsa == NULL) {
		fprintf(stderr, "Error while converting public key \n");
		exit(6);
	}
	/* get the TPM version and put into the bound structure */
	ret =
	    TPM_GetCapability(0x00000006, NULL, 0, &(bound.version[0]),
			      &i);
	if (ret != 0) {
		fprintf(stderr, "Error '%s' from TPM_GetCapability\n",
			TPM_GetErrMsg(ret));
		exit(7);
	}
	bound.type = 2;
	ret =
	    TSS_Bind(rsa, (unsigned char *) &bound, 5 + datlen, blob,
		     &bloblen);
	if (ret != 0) {
		fprintf(stderr, "Error '%s' from TSS_Bind\n",
			TPM_GetErrMsg(ret));
		exit(8);
	}
	ofile = fopen(argv[3], "w");
	if (ofile == NULL) {
		fprintf(stderr, "Unable to open output file '%s'\n",
			argv[3]);
		exit(9);
	}
	i = fwrite(blob, 1, bloblen, ofile);
	if (i != bloblen) {
		fprintf(stderr, "Error writing output file '%s'\n",
			argv[3]);
		fclose(ofile);
		exit(10);
	}
	fclose(ofile);
	exit(0);
}
