/*
 * libtpm: sign file test program
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
#include <getopt.h>
#include "tpmfunc.h"
#include <openssl/sha.h>

#define	VALID_ARGS	"k:?"

static int ParseArgs(int argc, char *argv[]);
static void usage();

static char *keypass = NULL;

int main(int argc, char *argv[])
{
	int ret;
	unsigned char databuff[65535];	/* data read work buffer */
	uint32_t parhandle;	/* handle of parent key */
	unsigned char passhash[20];	/* hash of parent key password */
	unsigned char datahash[20];	/* hash of data file */
	unsigned char sig[4096];	/* resulting signature */
	unsigned int siglen;	/* signature length */
	unsigned char *passptr;
	SHA_CTX sha;
	FILE *infile;
	FILE *sigfile;

	int nxtarg;

	nxtarg = ParseArgs(argc, argv);
	if (argc < (nxtarg + 3))
		usage();
	TPM_setlog(0);		/* turn off verbose output */
	/*
	 ** convert parent key handle from hex
	 */
	ret = sscanf(argv[nxtarg + 0], "%x", &parhandle);
	if (ret != 1) {
		fprintf(stderr, "Invalid argument '%s'\n",
			argv[nxtarg + 0]);
		exit(2);
	}
	/*
	 ** use SHA1 hash of password string as Key Authorization Data
	 */
	if (keypass != NULL) {
		TSS_sha1(keypass, strlen(keypass), passhash);
		passptr = passhash;
	} else
		passptr = NULL;
	/*
	 ** read and hash the data file
	 */
	infile = fopen(argv[nxtarg + 1], "r");
	if (infile == NULL) {
		fprintf(stderr, "Unable to open input file '%s'\n",
			argv[nxtarg + 1]);
		exit(2);
	}
	SHA1_Init(&sha);
	for (;;) {
		ret = fread(databuff, 1, sizeof databuff, infile);
		if (ret < 0) {
			fprintf(stderr,
				"I/O Error while reading input file '%s'\n",
				argv[nxtarg + 1]);
			exit(3);
		}
		SHA1_Update(&sha, databuff, ret);
		if (ret < sizeof databuff)
			break;
	}
	fclose(infile);
	SHA1_Final(datahash, &sha);
	ret = TPM_Sign(parhandle,	/* Key Handle */
		       passptr,		/* key Password */
		       datahash, sizeof(datahash),
		       sig, &siglen);
	if (ret != 0) {
		printf("Error %s from TPM_Sign\n", TPM_GetErrMsg(ret));
		exit(1);
	}
	sigfile = fopen(argv[nxtarg + 2], "w");
	if (sigfile == NULL) {
		fprintf(stderr, "Unable to open output file '%s'\n",
			argv[nxtarg + 2]);
		exit(4);
	}
	ret = fwrite(sig, 1, siglen, sigfile);
	if (ret != siglen) {
		fprintf(stderr,
			"I/O Error while writing output file '%s'\n",
			argv[nxtarg + 2]);
		exit(5);
	}
	fclose(sigfile);
	exit(0);
}

/**************************************************************************/
/*                                                                        */
/*  Parse Arguments                                                       */
/*                                                                        */
/**************************************************************************/
static int ParseArgs(int argc, char *argv[])
{
	extern char *optarg;
	extern int optind;
	int opt;

	if (argc == 2 && *argv[1] == '?')
		usage();
	/*
	 * Loop over the command line looking for arguments.
	 */
	while ((opt = getopt(argc, argv, VALID_ARGS)) != -1) {
		switch (opt) {
		case 'k':
			if (*optarg == '-') {
				fprintf(stderr,
					"option -k missing an argument\n");
				usage();
			}
			keypass = optarg;
			break;
		case '?':
		default:
			usage();
		}
	}
	return optind;
}

static void usage()
{
	fprintf(stderr,
		"Usage: signfile [options] <key handle in hex> <input file> <output file>\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "   Where the arguments are...\n");
	fprintf(stderr, "    <keyhandle>   is the key handle in hex\n");
	fprintf(stderr,
		"    <input file>  is the file containing the data to be signed\n");
	fprintf(stderr,
		"    <output file> is the file to contain the signed data\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "   Where the <options> are...\n");
	fprintf(stderr,
		"    -k <keypass>      to specify the key use password\n");
	fprintf(stderr,
		"    -?                print usage information (this message)\n");
	exit(1);
}
