/*
 * libtpm: unbind test program
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

#define	VALID_ARGS	"k:?"

static int ParseArgs(int argc, char *argv[]);
static void usage();

static char *keypass = NULL;

/**************************************************************************/
/*                                                                        */
/*  Main Program                                                          */
/*                                                                        */
/**************************************************************************/
int main(int argc, char *argv[])
{
	int ret;
	unsigned char databuff[256];	/* encrypted data read work buffer */
	unsigned char blob[256];	/* un-encrypted blob */
	int datlen;
	int bloblen;
	uint32_t parhandle;	/* handle of parent key */
	unsigned char passhash[20];	/* hash of parent key password */
	unsigned char *passptr;
	struct stat sbuf;
	FILE *infile;
	FILE *outfile;
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
	 ** get size of data file
	 */
	stat(argv[nxtarg + 1], &sbuf);
	datlen = (int) sbuf.st_size;
	/*
	 ** read the data file
	 */
	infile = fopen(argv[nxtarg + 1], "r");
	if (infile == NULL) {
		fprintf(stderr, "Unable to open data file '%s'\n",
			argv[nxtarg + 1]);
		exit(3);
	}
	ret = fread(databuff, 1, datlen, infile);
	fclose(infile);
	if (ret != datlen) {
		fprintf(stderr, "Unable to read data file\n");
		exit(4);
	}
	ret =
	    TPM_UnBind(parhandle, passptr, databuff, datlen, blob,
		       &bloblen);
	if (ret != 0) {
		fprintf(stderr, "Error '%s' from TPM_UnBind\n",
			TPM_GetErrMsg(ret));
		exit(5);
	}
	outfile = fopen(argv[nxtarg + 2], "w");
	if (outfile == NULL) {
		fprintf(stderr, "Unable to open output file '%s'\n",
			argv[nxtarg + 2]);
		exit(6);
	}
	ret = fwrite(blob, 1, bloblen, outfile);
	if (ret != bloblen) {
		fprintf(stderr, "Error writing output file '%s'\n",
			argv[nxtarg + 2]);
		fclose(outfile);
		exit(7);
	}
	fclose(outfile);
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
		"Usage: unbindfile [options] <key handle in hex> <input file> <outputfile>\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "   Where the arguments are...\n");
	fprintf(stderr, "    <keyhandle>   is the key handle in hex\n");
	fprintf(stderr,
		"    <input file>  is the file containing the data to be unbound\n");
	fprintf(stderr,
		"    <output file> is the file to contain the unbound data\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "   Where the <options> are...\n");
	fprintf(stderr,
		"    -k <keypass>      to specify the key use password\n");
	fprintf(stderr,
		"    -?                print usage information (this message)\n");
	exit(1);
}
