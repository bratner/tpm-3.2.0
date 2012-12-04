/*
 * libtpm: list keys test program
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

	TPM_setlog(0);
	ret =
	    TPM_GetCapability(0x0000007, NULL, 0,
			      (unsigned char *) listbuff, &listlen);
	if (ret != 0) {
		printf("Error %s from TPM_GetCapability\n",
		       TPM_GetErrMsg(ret));
		exit(1);
	}
	listsize = LOAD16(listbuff, 0);
	offset = 2;
	for (i = 0; i < listsize; ++i) {
		handle = LOAD32(listbuff, offset);
		printf("Key handle %02d %08X\n", i, handle);
		offset += 4;
	}
	exit(0);
}
