/*
 * libtpm: demo test program
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
#include <tpmfunc.h>	/* using TPM_Transmit, TPM_reset, and TPM_setlog */

uint32_t TPM_GetCapability_Version(int *major, int *minor, int *version,
				   int *rev)
{
	unsigned char blob[4096] = {
		0, 193,		/* TPM_TAG_RQU_COMMAND */
		0, 0, 0, 18,	/* blob length, bytes */
		0, 0, 0, 101,	/* TPM_ORD_GetCapability */
		0, 0, 0, 6,	/* TCPA_CAP_VERSION */
		0, 0, 0, 0	/* no sub capability */
	};
	uint32_t ret;
	ret = TPM_Transmit(blob, "TPM_GetCapability_Version");
	if (ret)
		return (ret);
	*major = (int) (blob[14]);
	*minor = (int) (blob[15]);
	*version = (int) (blob[16]);
	*rev = (int) (blob[17]);
	return (ret);
}

uint32_t TPM_GetCapability_Slots(uint32_t * slots)
{
	unsigned char blob[4096] = {
		0, 193,		/* TPM_TAG_RQU_COMMAND */
		0, 0, 0, 22,	/* blob length, bytes */
		0, 0, 0, 101,	/* TPM_ORD_GetCapability */
		0, 0, 0, 5,	/* TCPA_CAP_PROPERTY */
		0, 0, 0, 4,	/* SUB_CAP size, bytes */
		0, 0, 1, 4	/* TCPA_CAP_PROP_SLOTS */
	};
	uint32_t ret;
	ret = TPM_Transmit(blob, "TPM_GetCapability_Slots");
	if (ret)
		return (ret);
	*slots = ntohl(*(uint32_t *) (blob + 14));
	return (ret);
}

uint32_t TPM_GetCapability_Pcrs(uint32_t * pcrs)
{
	unsigned char blob[4096] = {
		0, 193,		/* TPM_TAG_RQU_COMMAND */
		0, 0, 0, 22,	/* blob length, bytes */
		0, 0, 0, 101,	/* TPM_ORD_GetCapability */
		0, 0, 0, 5,	/* TCPA_CAP_PROPERTY */
		0, 0, 0, 4,	/* SUB_CAP size, bytes */
		0, 0, 1, 1	/* TCPA_CAP_PROP_PCR */
	};
	uint32_t ret;
	ret = TPM_Transmit(blob, "TPM_GetCapability_Pcrs");
	if (ret)
		return (ret);
	*pcrs = ntohl(*(uint32_t *) (blob + 14));
	return (ret);
}

uint32_t TPM_GetCapability_Key_Handle(uint16_t * num, uint32_t keys[])
{
	unsigned char blob[4096] = {
		0, 193,		/* TPM_TAG_RQU_COMMAND */
		0, 0, 0, 18,	/* blob length, bytes */
		0, 0, 0, 101,	/* TPM_ORD_GetCapability */
		0, 0, 0, 7,	/* TCPA_CAP_KEY_HANDLE */
		0, 0, 0, 0	/* no sub capability */
	};
	uint32_t ret;
	int i;
	ret = TPM_Transmit(blob, "TPM_GetCapability_Handle_List");
	if (ret)
		return (ret);
	*num = ntohs(*(uint16_t *) (blob + 14));
	for (i = 0; i < *num; i++)
		keys[i] = ntohl(*(uint32_t *) (blob + 16 + 4 * i));
	return (ret);
}

int main(int argc, char *argv[])
{
	pubkeydata pubek;
	uint32_t slots;
	uint32_t pcrs;
	uint16_t num;
	uint32_t keys[256];
	unsigned char pcr_data[20];
	int major, minor, version, rev, i, j;

	TPM_setlog(0);

	if (TPM_Reset())
		exit(-1);
	printf("TPM successfully reset\n");

	if (TPM_GetCapability_Version(&major, &minor, &version, &rev))
		exit(-1);
	printf("TPM version %d.%d.%d.%d\n", major, minor, version, rev);

	if (TPM_GetCapability_Pcrs(&pcrs))
		exit(-1);
	printf("%d PCR registers are available\n", pcrs);
	for (i = 0; i < pcrs; i++) {
		if (TPM_PcrRead((uint32_t) i, pcr_data))
			exit(-1);
		printf("PCR-%02d: ", i);
		for (j = 0; j < 20; j++)
			printf("%02X ", pcr_data[j]);
		printf("\n");
	}

	if (TPM_GetCapability_Slots(&slots))
		exit(-1);
	printf("%d Key slots are available\n", slots);

	if (TPM_GetCapability_Key_Handle(&num, keys))
		exit(-1);
	if (num == 0)
		printf("No keys are loaded\n");
	else
		for (i = 0; i < num; i++)
			printf("Key Handle %04X loaded\n", keys[i]);

	if (TPM_ReadPubek(&pubek))
		printf("Unable to read Pubek\n");
	else {
		printf("Pubek keylength %d\nModulus:", pubek.keylength);
		for (i = 0; i < pubek.keylength; i++) {
			if (!(i % 16))
				printf("\n");
			printf("%02X ", pubek.modulus[i]);
		}
		printf("\n");
	}

	return (0);
}
