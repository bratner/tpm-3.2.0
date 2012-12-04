/*
 * libtpm: change tpm auth test program
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
#include <string.h>
#include <unistd.h>
#include "tpmfunc.h"


#define	VALID_ARGS	"o?"

static int ParseArgs(int argc, char *argv[]);
static void usage();

static int ownflag = 0;

int main(int argc, char *argv[])
{
	int ret;
	unsigned char *ownpass;
	unsigned char *newpass;
	unsigned char ownphash[20];
	unsigned char newphash[20];

	int nxtarg;
	/*
	 **  parse command line
	 */
	nxtarg = ParseArgs(argc, argv);
	if (argc < (nxtarg + 2))
		usage();
	ownpass = argv[nxtarg + 0];
	newpass = argv[nxtarg + 1];
	TPM_setlog(0);
	/*
	 ** use the SHA1 hash of the password string as the TPM Owner Password
	 */
	TSS_sha1(ownpass, strlen(ownpass), ownphash);
	/*
	 ** use SHA1 hash of password string as New Authorization Data
	 */
	TSS_sha1(newpass, strlen(newpass), newphash);
	if (ownflag) {
		ret = TPM_ChangeOwnAuth(ownphash, newphash);
		if (ret != 0) {
			fprintf(stderr,
				"Error %s from TPM_ChangeOwnAuth\n",
				TPM_GetErrMsg(ret));
			exit(1);
		}
	} else {
		ret = TPM_ChangeSRKAuth(ownphash, newphash);
		if (ret != 0) {
			fprintf(stderr,
				"Error %s from TPM_ChangeSRKAuth\n",
				TPM_GetErrMsg(ret));
			exit(1);
		}
	}
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
		case 'o':
			ownflag = 1;
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
		"Usage: chgtpmauth [-o] <TPM owner password> <new SRK or Owner password>\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "   Where the <options> are...\n");
	fprintf(stderr,
		"    -o                to specify the TPM Owner password is to be changed\n");
	fprintf(stderr,
		"    -?                print usage information (this message)\n");
	exit(1);
}
