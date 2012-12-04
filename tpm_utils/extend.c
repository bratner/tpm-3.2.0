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
	uint32_t pcrindex;
	unsigned char extendval[20]={0};	/* value to extend a pcr with */
	unsigned int bloblen;	/* blob length */

	if (argc < 2) {
		fprintf(stderr,
			"Usage: extend <pcr index> <pcr value> \n");
		exit(1);
	}
	/*
	 ** Parse and process the command line arguments
	 */
	/* convert parent key handle from hex */
	ret = sscanf(argv[1], "%x", &pcrindex);
	if (ret != 1) {
		fprintf(stderr, "Invalid argument '%s'\n", argv[1]);
		exit(2);
	}
	strncat(extendval, argv[2],19);
        printf("Extending pcr mask %x with string %s\n", pcrindex,extendval);
 	ret=TPM_Extend(pcrindex,extendval);
        printf("Returned %d\n",ret);
	
	exit(0);
}
