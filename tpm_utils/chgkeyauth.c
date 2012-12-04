/*
 * libtpm: change key auth test program
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
#include <string.h>
#include <netinet/in.h>
#include <unistd.h>
#include <getopt.h>
#include "tpmfunc.h"

#define	VALID_ARGS	"p:?"

static int ParseArgs(int argc, char *argv[]);
static void usage();

static char *parpass = NULL;

int main(int argc, char *argv[])
{
	int ret;
	struct stat sbuf;
	unsigned char keyblob[4096];
	unsigned int keyblen;
	unsigned char outblob[4096];
	unsigned int outblen;
	unsigned int handle;
	unsigned char filename[256];
	unsigned char filename2[256];
	unsigned char parphash[20];
	unsigned char newphash[20];
	unsigned char keyphash[20];
	unsigned char *passptr1;
	FILE *outfile;
	FILE *ainfile;
	keydata key;
	unsigned char *keypass;
	unsigned char *newpass;
	unsigned char *keyname;
	unsigned char *parhndl;

	int nxtarg;

	nxtarg = ParseArgs(argc, argv);
	if (argc < (nxtarg + 4))
		usage();
	TPM_setlog(0);
	parhndl = argv[nxtarg + 0];
	keyname = argv[nxtarg + 1];
	keypass = argv[nxtarg + 2];
	newpass = argv[nxtarg + 3];
	/*
	 ** convert parent key handle from hex
	 */
	ret = sscanf(parhndl, "%x", &handle);
	if (ret != 1) {
		fprintf(stderr, "Invalid argument '%s'\n", parhndl);
		exit(2);
	}
	/*
	 * use SHA1 hash of password string as Parent Key Authorization 
	 */
	if (parpass != NULL) {
		TSS_sha1(parpass, strlen(parpass), parphash);
		passptr1 = parphash;
	} else
		passptr1 = NULL;
	/*
	 ** use SHA1 hash of password string as Key Authorization Data
	 */
	TSS_sha1(keypass, strlen(keypass), keyphash);
	/*
	 ** use  SHA1 hash of password string as New Authorization Data
	 */
	TSS_sha1(newpass, strlen(newpass), newphash);
	/*
	 ** read the key blob
	 */
	ainfile = fopen(keyname, "r");
	if (ainfile == NULL) {
		fprintf(stderr, "Unable to open key file\n");
		exit(3);
	}
	stat(keyname, &sbuf);
	keyblen = (int) sbuf.st_size;
	ret = fread(keyblob, 1, keyblen, ainfile);
	if (ret != keyblen) {
		fprintf(stderr, "Unable to read key file\n");
		exit(4);
	}
	fclose(ainfile);
	TSS_KeyExtract(keyblob, &key);
	ret = TPM_ChangeAuth(handle, passptr1, keyphash, newphash, &key);
	if (ret != 0) {
		fprintf(stderr, "Error %s from TPM_ChangeAuth\n",
			TPM_GetErrMsg(ret));
		exit(5);
	}
	ret = TPM_BuildKey(outblob, &key);
	if ((ret & ERR_MASK) != 0)
		return ret;
	outblen = ret;
	sprintf(filename2, "%s.save", keyname);
	sprintf(filename, "%s", keyname);
	ret = rename(filename, filename2);
	if (ret != 0) {
		fprintf(stderr, "Unable to rename old key file\n");
		exit(6);
	}
	outfile = fopen(filename, "w");
	if (outfile == NULL) {
		fprintf(stderr, "Unable to create new key file\n");
		exit(7);
	}
	ret = fwrite(outblob, 1, outblen, outfile);
	if (ret != outblen) {
		fprintf(stderr, "Unable to write new key file\n");
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
		case 'p':
			if (*optarg == '-') {
				fprintf(stderr,
					"option -p missing an argument\n");
				usage();
			}
			parpass = optarg;
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
		"Usage: chgkeyauth [options] <parent key handle> <key file name> <old key password> <new key password>\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "   Where the arguments are...\n");
	fprintf(stderr,
		"    <parent key handle>   is the parent key handle in hex\n");
	fprintf(stderr,
		"    <key file name>       is the name of the key file\n");
	fprintf(stderr,
		"    <old key password>    is the current key password\n");
	fprintf(stderr,
		"    <new key password>    is the new key password\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "   Where the <options> are...\n");
	fprintf(stderr,
		"    -p <parpass>      to specify the parent key use password\n");
	fprintf(stderr,
		"    -?                print usage information (this message)\n");
	exit(1);
}
