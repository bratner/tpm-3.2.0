/*
 * libtpm: take ownership test program
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
	int ret;
	unsigned char ibm_pass[] = "SRK PWD\0";
	unsigned char pass1hash[20];
	unsigned char pass2hash[20];
	keydata srk;
	RSA *rsa;		/* OpenSSL format Public Key */
	FILE *keyfile;		/* output file for public key */
	EVP_PKEY pkey;		/* OpenSSL public key */

	if (argc < 2) {
		fprintf(stderr,
			"Usage: takeown [-i] <owner password>"
			" [<storage root key password>]\n");
		exit(1);
	}
	TPM_setlog(0);		/* turn off verbose output */

	if(argc==2){ 
		TSS_sha1(argv[1], strlen(argv[1]), pass1hash);
		ret = TPM_TakeOwnership(pass1hash, NULL, &srk);
	}
	if((argc==3) && (argv[1][0]=='-') && (argv[1][1]=='i')){
		TSS_sha1(ibm_pass, 8, pass2hash);
		ret = TPM_TakeOwnership(pass1hash, pass2hash, &srk);
	} else if(argc==3){
		TSS_sha1(argv[2],strlen(argv[2]),pass2hash);
		ret = TPM_TakeOwnership(pass1hash,pass2hash,&srk);
	} else if (argc>3){
		printf("usage takeown [-i] ownerpass [srkpass]\n");
		exit(-1);
	}

	if (ret != 0) {
		fprintf(stderr, "Error %s from TPM_TakeOwnership\n",
			TPM_GetErrMsg(ret));
		exit(-2);
	}		
	/*
	 ** convert the returned public key to OpenSSL format and
	 ** export it to a file
	 */
	rsa = TSS_convpubkey(&(srk.pub));
	if (rsa == NULL) {
		fprintf(stderr, "Error from TSS_convpubkey\n");
		exit(-3);
	}
	OpenSSL_add_all_algorithms();
	EVP_PKEY_assign_RSA(&pkey, rsa);
	keyfile = fopen("srk.pem", "w");
	if (keyfile == NULL) {
		fprintf(stderr, "Unable to create public key file\n");
		exit(-4);
	}
	ret = PEM_write_PUBKEY(keyfile, &pkey);
	if (ret == 0) {
		fprintf(stderr, "Unable to write public key file\n");
		exit(-5);
	}
	fclose(keyfile);
	RSA_free(rsa);
	exit(0);
}
