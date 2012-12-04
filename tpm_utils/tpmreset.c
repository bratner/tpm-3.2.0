/*
 * libtpm: tpm reset test program
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
#include "tpm.h"
#include "tpmutil.h"

static unsigned char reset_fmt[] = "00 c1 T 00 00 00 5A";

int main(int argc, char *argv[])
{
	int ret;
	unsigned char tcpadata[TPM_MAX_BUFF_SIZE];

	ret = TSS_buildbuff(reset_fmt, tcpadata);
	if ((ret & ERR_MASK) != 0) {
		printf("Error %x from buildbuff\n", ret);
		exit(6);
	}
	ret = TPM_Transmit(tcpadata, "Reset");
	exit(ret);
}
