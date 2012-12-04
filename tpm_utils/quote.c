/*
 * libtpm: TPM_Quote test program
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
	unsigned char capdata[4];	/* returned TPM version  */
	unsigned int caplen;	/* length of TPM version */
	pubkeydata pubkey;	/* public key structure */
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

	TPM_setlog(0);		/* turn off verbose output from TPM driver */
	if (argc < 3) {
		fprintf(stderr,
			"Usage: quote <key handle in hex> <pcr mask in hex> [<key password>]\n");
		exit(1);
	}
	/*
	 ** Parse and process the command line arguments
	 */
	/* convert parent key handle from hex */
	ret = sscanf(argv[1], "%x", &parhandle);
	if (ret != 1) {
		fprintf(stderr, "Invalid argument '%s'\n", argv[1]);
		exit(2);
	}
	/* get SHA1 hash of password string for Key Authorization Data */
	if (argc > 3) {
		TSS_sha1(argv[3], strlen(argv[3]), passhash1);
		passptr = passhash1;
	} else
		passptr = NULL;
	/* for testing, use the password hash as the test nonce */
	memcpy(data, passhash1, 20);
	/* convert pcr mask from hex */
	ret = sscanf(argv[2], "%x", &pcrmask);
	if (ret != 1) {
		fprintf(stderr, "Invalid argument '%s'\n", argv[2]);
		exit(2);
	}


	/*
	 ** perform the TPM Quote function
	 */
	ret = TPM_Quote(parhandle,	/* KEY handle */
			pcrmask,	/* specify PCR registers */
			passptr,	/* Key Password (hashed), or null */
			data,	/* nonce data */
			pcrcompos,	/* pointer to pcr composite */
			blob, &bloblen);	/* buffer to receive result */
	if (ret != 0) {
		printf("Error '%s' from TPM_Quote\n", TPM_GetErrMsg(ret));
		exit(6);
	}


	/*
	 ** Get the public key and convert to an OpenSSL RSA public key
	 */
	ret =
	    TPM_GetPubKey(parhandle, passptr, pubkeyblob, &pubkeybloblen);
	if (ret != 0) {
		printf("Error '%s' from TPM_GetPubKey\n",
		       TPM_GetErrMsg(ret));
		exit(6);
	}
	TSS_PubKeyExtract(pubkeyblob, &pubkey, 0);
	rsa = TSS_convpubkey(&pubkey);


	/*
	 ** fill the quote info structure and calculate the hashes
	 */
	memcpy(&(quoteinfo.fixed), "QUOT", 4);
	memcpy(&(quoteinfo.nonce), data, 20);
	/* get tcpa version */
	ret = TPM_GetCapability(0x00000006, NULL, 0, capdata, &caplen);
	if (ret != 0) {
		printf("Error '%s' from TPM_GetCapability\n",
		       TPM_GetErrMsg(ret));
		exit(6);
	}
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
