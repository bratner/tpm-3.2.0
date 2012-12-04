/*
 * libtpm: dump key test program
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
#include <unistd.h>
#include <netinet/in.h>
#include "tpmfunc.h"

int main(int argc, char *argv[])
{
	int ret;
	struct stat sbuf;
	unsigned char keyblob[4096];
	unsigned int keyblen;
	FILE *kinfile;
	keydata k;

	if (argc < 2) {
		fprintf(stderr, "Usage: dumpkey <key file name>\n");
		exit(1);
	}
	/*
	 ** read the Key File
	 */
	kinfile = fopen(argv[1], "r");
	if (kinfile == NULL) {
		fprintf(stderr, "Unable to open key file\n");
		exit(3);
	}
	stat(argv[1], &sbuf);
	keyblen = (int) sbuf.st_size;
	ret = fread(keyblob, 1, keyblen, kinfile);
	if (ret != keyblen) {
		fprintf(stderr, "Unable to read key file\n");
		exit(4);
	}
	fclose(kinfile);
	TSS_KeyExtract(keyblob, &k);
	printf("Version:        %02x%02x%02x%02x\n", k.version[0],
	       k.version[1], k.version[2], k.version[3]);
	printf("KeyUsage:       %02x\n", k.keyusage);
	printf("KeyFlags:       %04x\n", k.keyflags);
	printf("AuthDataUsage:  %02x\n", k.authdatausage);
	printf("Pub Algorithm:  %04x\n", k.pub.algorithm);
	printf("Pub EncScheme:  %02x\n", k.pub.encscheme);
	printf("Pub SigScheme:  %02x\n", k.pub.sigscheme);
	printf("Pub KeyBitLen:  %04x\n", k.pub.keybitlen);
	printf("Pub KeyLength:  %04x\n", k.pub.keylength);
	printf("Pub Exp Size:   %02X\n", k.pub.expsize);
	exit(0);
}
