/*
 * libtpm: unseal test program
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
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "tpmfunc.h"

#define	VALID_ARGS	"k:d:?"

static int ParseArgs(int argc, char *argv[]);
static void usage();

static char *keypass = NULL;
static char *datpass = NULL;


int main(int argc, char *argv[])
{
	int ret;
	struct stat sbuf;
	unsigned char databuff[256];	/* data buffer */
	unsigned int datalen;	/* size of data */
	uint32_t parhandle;	/* handle of parent key */
	unsigned char passhash1[20];	/* hash of parent key password */
	unsigned char passhash2[20];	/* hash of data       password */
	unsigned char blob[4096];	/* sealed blob */
	unsigned int bloblen;	/* blob length */
	unsigned char *passptr1;
	unsigned char *passptr2;
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
		TSS_sha1(keypass, strlen(keypass), passhash1);
		passptr1 = passhash1;
	} else
		passptr1 = NULL;
	/*
	 ** use SHA1 hash of password string as Blob Authorization Data
	 */
	if (datpass != NULL) {
		TSS_sha1(datpass, strlen(datpass), passhash2);
		passptr2 = passhash2;
	} else
		passptr2 = NULL;
	/*
	 ** get size of blob file
	 */
	stat(argv[nxtarg + 1], &sbuf);
	bloblen = (int) sbuf.st_size;
	/*
	 ** read the blob file
	 */
	infile = fopen(argv[nxtarg + 1], "r");
	if (infile == NULL) {
		fprintf(stderr, "Unable to open input file '%s'\n",
			argv[nxtarg + 1]);
		exit(4);
	}
	ret = fread(blob, 1, bloblen, infile);
	if (ret != bloblen) {
		fprintf(stderr,
			"I/O Error while reading input file '%s'\n",
			argv[nxtarg + 1]);
		exit(5);
	}
	ret = TPM_Unseal(parhandle,	/* KEY Entity Value */
			 passptr1,	/* Key Password */
			 passptr2,	/* blob password */
			 blob, bloblen,	/* encrypted blob, blob length */
			 databuff, &datalen);
	if (ret != 0) {
		printf("Error %s from TPM_Unseal\n", TPM_GetErrMsg(ret));
		exit(6);
	}
	outfile = fopen(argv[nxtarg + 2], "w");
	if (outfile == NULL) {
		fprintf(stderr, "Unable to open output file '%s'\n",
			argv[nxtarg + 2]);
		exit(7);
	}
	ret = fwrite(databuff, 1, datalen, outfile);
	if (ret != datalen) {
		fprintf(stderr,
			"I/O Error while writing output file '%s'\n",
			argv[nxtarg + 2]);
		exit(8);
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
		case 'd':
			if (*optarg == '-') {
				fprintf(stderr,
					"option -d missing an argument\n");
				usage();
			}
			datpass = optarg;
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
		"Usage: unsealfile [options] <key handle in hex> <input file> <outputfile>\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "   Where the arguments are...\n");
	fprintf(stderr, "    <keyhandle>   is the key handle in hex\n");
	fprintf(stderr,
		"    <input file>  is the file containing the data to be unsealed\n");
	fprintf(stderr,
		"    <output file> is the file to contain the unsealed data\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "   Where the <options> are...\n");
	fprintf(stderr,
		"    -k <keypass>      to specify the key use password\n");
	fprintf(stderr,
		"    -d <datpass>      to specify the data use password\n");
	fprintf(stderr,
		"    -?                print usage information (this message)\n");
	exit(1);
}
