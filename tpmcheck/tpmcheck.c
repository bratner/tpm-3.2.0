/* init_tpm
 *
 * init_tpm [path to bootkey directory, default /etc/bootkeys]
 *
 * This program checks the tpm, initializes compatibly with IBM CSS
 * as necessary, and creates a kernel master key (kmk),
 * saving copies of the sealing key and sealed kmk in bootkey directory.
 * The kmk is not loaded.
 *
 * Copyright (C) 2005 IBM Corporation
 * Author: David Safford <safford@watson.ibm.com>
 *
 *      This program is free software; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 2 of the License, or
 *      (at your option) any later version.
 */ 

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netinet/in.h>
#include "tpmfunc.h"
#include <tpmutil.h>
#include <tpmkeys.h>
#include <oiaposap.h>
#include <hmac.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>

/* constants from TPM */
#define TPM_SRK_HANDLE 0x40000000
#define TPM_MAX_KEY_SIZE 4096
#define TPM_MAX_BLOB_SIZE 4096
#define TPM_AUTH_SIZE 20
#define TPM_AUTHFAIL 1
#define TPM_DISABLED 7
#define TPM_NOSRK 18
#define TPM_BAD_KEY_PROPS 40
#define KMK_SIZE 20
#define PCR_MASK (1<<15)

/* default passwords for IBM CSS compatibility */
#define OWNPASS ""
#define SRKPASS ""

static unsigned char kmk[KMK_SIZE];
static unsigned char *pcrinfo;
static uint32_t pcrinfosize;
static unsigned char syspcr[TPM_MAX_BLOB_SIZE];  /* area to hold key blob */
static int unsigned syspcrlen;	     /* key blob length */
static unsigned char sealed[TPM_MAX_BLOB_SIZE];
static unsigned int seallen;
static int check_tpm(void);

int main(int argc,char *argv[])
{
	char *boot;
	char defboot[] = "/etc/bootkeys";
	unsigned char auth[20];

        #ifdef USERTEST
                TPM_setlog(1);
        #else
                TPM_setlog(0);
        #endif

	if(argc==1)
		boot=defboot;
	else if(argc==2)
		boot=argv[1];
	else {
		printf("Usage: init_tpm [path to bootkey dir]\n");
		exit(-1);
	}

	memset(auth,0,sizeof(auth));
	printf("Running check_tpm() - returned %d\n",check_tpm());

	exit(0);
}

/*
 *  check_tpm 
 *
 *  This program is used to check and initialize the
 *  TPM (if any) on a machine, as part of installation.
 *  It determines if:
 *      /dev/tpm0 exists (the driver has been loaded)
 *      the TPM is communicating properly
 *      the TPM is enabled in BIOS
 *      the TPM already has an owner (or not)
 *      if the TPM has an owner, if the supplied SRK password is correct
 *      
 *  It assumes modprobe tpm_atmel has already been done...
 *  It provides the following output and return codes:
 *
 *  Return Code/Message to stdout        Meaning
 *    -1 "Unable to open /dev/tpm0"      (no TPM)
 *    -2 "TPM_Reset failed <error>"      (bad TPM)
 *    -3 "TPM_PcrRead failed <error>"    (ask user to "enable" TPM in BIOS)
 *    -4 "TPM already has unknown owner" (ask user to "clear" TPM in BIOS)
 *    -5 "Undexpected return code"       (quit)
 *  Success return codes 
 *    0 "TPM is IBM CSS managed"         (default SRK password works)
 *    1 "TPM initialized"                (takeown succeeded)
 *
 *  Normal installation usage:
 *    Run check_tpm with no arguments.
 *       -1 means there is no TPM, so TLC not possible
 *       -2 means the TPM is bad, give message to user
 *       -3 means the TPM is disabled in BIOS, give message to user
 *       -4 means TPM already has owner (and it's not IBM CSS)
 *              ask user to clear TPM
 *        0 means TPM is owned by IBM CSS, ready for createkernkey
 *        1 means TPM is now initialized, do createkernkey
 *
 *  Algorithm:
 *     The TPM does not have commands to test for an owner, or
 *     to test for correct passwords, so other commands have to 
 *     be run, and the return codes inspected to infer status.
 *     The TPM_reset command should always succeed, even if the
 *     TPM is disabled. The TPM PcrRead command should always
 *     succeed, so long as the TPM is enabled. The owner and
 *     password can be infered by trying a TPM_CreateWrapKey
 *     command and checking the failure codes. To avoid
 *     potentially long delays should the command succeed,
 *     the key parameters are deliberately invalid.
 */

static int check_tpm(void)
{
	unsigned char keybuf[TPM_MAX_KEY_SIZE];
	unsigned char pcrvalue[TPM_AUTH_SIZE];
	unsigned char srkauth[TPM_AUTH_SIZE];
	uint32_t ret, srk_handle;
	unsigned int keylen;
	keydata k, key;
	int tpmfp;

	/* check /dev/tpm0 */
        if ((tpmfp = open("/dev/tpm0", O_RDWR)) < 0) {
		printf("Unable to open /dev/tpm0\n");
                exit(-1);
        }
	close(tpmfp);

	/* try a TPM_Reset (should work even if TPM disabled) */
	if((ret=TPM_Reset())){
		printf("TPM_Reset failed, error %s\n", TPM_GetErrMsg(ret));
		exit(-2);
	}

	/* check if TPM enabled with TPM_PcrRead */
	if((ret=TPM_PcrRead(0L,pcrvalue))){
		printf("TPM_PcrRead failed, error %s\n", TPM_GetErrMsg(ret));
		exit(-3);
	}

	/* check if TPM already has default IBM CSS owner */
	srk_handle=TPM_SRK_HANDLE;
	TSS_sha1((unsigned char *)SRKPASS,8,srkauth);
       	k.keyflags = 0;
       	k.authdatausage = 0;    /* key requires no password */
       	k.privkeylen = 0;       /* no private key specified here */
       	k.pub.algorithm = 0x00000099;   /* BOGUS ALG */
       	k.keyusage = 0x0014;    /* key Usage - 0x0014 = bind */
       	k.pub.encscheme = 0x0003;       /* encryption scheme 3 RSA */
       	k.pub.sigscheme = 0x0001;       /* signature scheme none */
       	k.pub.keybitlen = 2048; /* RSA modulus size 2048 bits */
       	k.pub.numprimes = 2;    /* required */
       	k.pub.expsize = 0;      /* RSA exponent - default 0x010001 */
       	k.pub.keylength = 0;    /* key not specified here */
       	k.pub.pcrinfolen = 0;   /* no PCR's used at this time */
	ret=TPM_CreateWrapKey(srk_handle,srkauth,
		NULL,NULL, &k,&key,keybuf,&keylen);
	if(ret==TPM_AUTHFAIL){
		printf("TPM already has unknown owner\n"),
		exit(-4);
	}
	if(ret==TPM_BAD_KEY_PROPS){
		printf("TPM is already IBM CSS managed\n");
		return(0);
	}
	if(ret==TPM_NOSRK){
			printf("TPM is already owned\n");
			return(1);
		
	}
	printf("Unexpected return code %d\n",ret);
	exit(-5);
}
