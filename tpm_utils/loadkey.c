/*
 * libtpm: loadkey test program
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

int main(int argc, char *argv[])
{
	int ret;
	struct stat sbuf;
	unsigned char pass1hash[20];
	unsigned char keyblob[4096];
	unsigned int keyblen;
	unsigned int handle;
	unsigned int newhandle;
	unsigned char *pptr = NULL;
	FILE *kinfile;
	keydata k;

	if (argc < 3) {
		fprintf(stderr,
			"Usage: loadkey <parent key handle> <key file name> [<parent key password>]\n");
		exit(1);
	}
	/*
	 ** convert parent key handle from hex
	 */
	ret = sscanf(argv[1], "%x", &handle);
	if (ret != 1) {
		fprintf(stderr, "Invalid argument '%s'\n", argv[1]);
		exit(2);
	}
	/*
	 ** use SHA1 hash of parent key pass string as Key Authorization Data
	 */
	if (argc > 3) {
		TSS_sha1(argv[3], strlen(argv[3]), pass1hash);
		pptr = pass1hash;
	}
	/*
	 ** read the Key File
	 */
	kinfile = fopen(argv[2], "r");
	if (kinfile == NULL) {
		fprintf(stderr, "Unable to open key file\n");
		exit(3);
	}
	stat(argv[2], &sbuf);
	keyblen = (int) sbuf.st_size;
	ret = fread(keyblob, 1, keyblen, kinfile);
	if (ret != keyblen) {
		fprintf(stderr, "Unable to read key file\n");
		exit(4);
	}
	fclose(kinfile);
	TSS_KeyExtract(keyblob, &k);
	TPM_setlog(0);
	ret = TPM_LoadKey(handle, pptr, &k, &newhandle);
	if (ret != 0) {
		fprintf(stderr, "Error %s from TPM_LoadKey\n",
			TPM_GetErrMsg(ret));
		exit(6);
	}
	fprintf(stdout, "%08X\n", newhandle);
	exit(0);
}
