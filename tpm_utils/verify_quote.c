/*
 * libtpm: verify_quote program
 *
 * Copyright (C) 2010 Boris Ratner
 * Author: Boris Ratner
 *
 *      This program is free software; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 2 of the License, or
 *      (at your option) any later version.
 */


#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include "tpmfunc.h"
#include <openssl/pem.h>
#include <openssl/rsa.h>

int main(int argc, char *argv[])
{
	int ret;		/* general return value */
	uint32_t parhandle;	/* handle of parent key */
	unsigned int pcrmask;	/* pcr register mask */
	unsigned char passhash1[20];	/* hash of parent key password */
	unsigned char data[20];	/* nonce data */

	unsigned char blob[4096];	/* resulting signature blob */
	unsigned int bloblen;	/* blob length */
	unsigned char pcrcompos[4096];	/* returned pcr composite structure */
	unsigned char pubkeyblob[4096];	/* public portion of key blob */
	unsigned int pubkeybloblen;	/* length of public key blob */
	unsigned char capdata[4]={1,1,0,0};	/* MUST be 1.1.0.0  */
	pubkeydata pubkey;	/* public key structure */
	EVP_PKEY *pkey;
	RSA *rsa;		/* openssl RSA public key */
	struct quote_info {	/* quote info structure */
		unsigned char version[4];
		unsigned char fixed[4];
		unsigned char comphash[20];
		unsigned char nonce[20];
	} quoteinfo;
	unsigned char sighash[20];	/* hash of quote info structure */
	unsigned char *passptr;

	unsigned int len1;
	unsigned int len2;
	FILE *keyfile;
	FILE *sigfile;
	FILE *pcrfile;

	char filename[128]={0};

	
	if (argc < 3) {
		fprintf(stderr,
			"Usage: verify_quote <quote name> <nonce> <keyfile>\n");
		exit(1);
	}
	
	/* Read and decode the public key file */

	keyfile = fopen(argv[3],"r");
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
	fclose(keyfile);
	
	/* Read the signature file */

        snprintf(filename,128,"%s.sig",argv[1]);
        sigfile = fopen(filename,"r");
        if(sigfile == NULL) {
                fprintf(stderr,"Unable to open %s file.\n",filename);
                exit(1);
        }

        bloblen = fread(blob, 1, sizeof(blob), sigfile );
        if (!feof(sigfile)) {
                fprintf(stderr, "I/O Error reading sig file\n");
                exit(1);
        }
        fclose(sigfile);

	/* Read the pcr file */

	snprintf(filename,128,"%s.pcrs",argv[1]);
        pcrfile = fopen(filename,"r");
        if(pcrfile == NULL) {
                fprintf(stderr,"Unable to open %s file.\n",filename);
                exit(1);
        }

        fread(pcrcompos, 1, sizeof(pcrcompos), pcrfile );
        if (!feof(pcrfile)) {
                fprintf(stderr, "I/O Error reading pcr file\n");
                exit(1);
        }
        fclose(pcrfile);


	
        /* use the nonce hash as the test nonce to prevent replay attacks*/
        TSS_sha1(argv[2], strlen(argv[2]), data);

	/*
	 ** fill the quote info structure and calculate the hashes
	 */
	memcpy(&(quoteinfo.fixed), "QUOT", 4);
	memcpy(&(quoteinfo.nonce), data, 20);
	memcpy(&(quoteinfo.version), capdata, 4);

	/* get the length of the PCR composite structure */
	len1 = LOAD16(pcrcompos, 0);
	len2 = LOAD32(pcrcompos, 2 + len1);
	/* create hash of the PCR_composite data for quoteinfo structure */
	TSS_sha1(pcrcompos, len1 + len2 + 2 + 4, quoteinfo.comphash);
	/* create hash of quoteinfo structure for signature verification */
	TSS_sha1((unsigned char *) &quoteinfo, sizeof(struct quote_info),
		 sighash);

	/*
	 ** perform an RSA verification on the signature returned by Quote
	 */
	ret = RSA_verify(NID_sha1, sighash, 20, blob, bloblen, rsa);
	if (ret != 1) {
		fprintf(stderr, "Verification Failed\n");
		exit(100);
	}
	fprintf(stderr, "Verification Succeeded\n");
	RSA_free(rsa);
	exit(0);
}
