/*
 * libtpm: clear owner test program
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

int main(int argc, char *argv[])
{
	int ret;
	unsigned char passhash[20];

	if (argc < 2) {
		fprintf(stderr, "Usage: clearown <owner password>\n");
		exit(1);
	}
	TPM_setlog(0);
	/*
	 ** use SHA1 hash of password string as Owner Authorization Data
	 */
	TSS_sha1(argv[1], strlen(argv[1]), passhash);
	ret = TPM_OwnerClear(passhash);
	if (ret != 0) {
		fprintf(stderr, "Error %s from TPM_OwnerClear\n",
			TPM_GetErrMsg(ret));
		exit(1);
	}
	exit(0);
}
