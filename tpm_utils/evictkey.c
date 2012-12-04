/*
 * libtpm: evictkey test program
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
#include <netinet/in.h>
#include "tpmfunc.h"

int main(int argc, char *argv[])
{
	int ret;
	uint32_t handle;
	unsigned char listbuff[1024];
	uint32_t listlen;
	int i;
	int listsize;
	int offset;

	if (argc < 2) {
		fprintf(stderr,
			"Usage: evictkey <key handle in hex>| all\n");
		exit(1);
	}
	TPM_setlog(0);
	if (strcasecmp("all", argv[1]) == 0) {
		/* must evict all keys */
		ret =
		    TPM_GetCapability(0x0000007, NULL, 0,
				      (unsigned char *) listbuff,
				      &listlen);
		if (ret != 0) {
			fprintf(stderr,
				"Error %x from TPM_GetCapability\n", ret);
			exit(1);
		}
		listsize = LOAD16(listbuff, 0);
		offset = 2;
		for (i = 0; i < listsize; ++i) {
			handle = LOAD32(listbuff, offset);
			ret = TPM_EvictKey(handle);
			if (ret == 0)
				printf("Evicted key handle %08X\n",
				       handle);
			else
				printf
				    ("Error %s in Evict key handle %08X\n",
				     TPM_GetErrMsg(ret), handle);
			offset += 4;
		}
		exit(0);
	}
	ret = sscanf(argv[1], "%x", &handle);
	if (ret != 1) {
		fprintf(stderr, "Invalid argument '%s'\n", argv[1]);
		exit(2);
	}
	ret = TPM_EvictKey(handle);
	if (ret != 0) {
		fprintf(stderr, "Error %s from TPM_EvictKey\n",
			TPM_GetErrMsg(ret));
		exit(1);
	}
	exit(0);
}
