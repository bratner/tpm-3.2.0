/*
 * libtpm: create key test program
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
#include <unistd.h>
#include "tpmfunc.h"
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>

#define	VALID_ARGS	"k:m:p:t:i?"

static int ParseArgs(int argc, char *argv[]);
static void usage();

static char keytype = 's';
static int ibm_default = 0;

static char *migpass = NULL;
static char *parpass = NULL;
static char *keypass = NULL;

/**************************************************************************/
/*                                                                        */
/*  Main Program                                                          */
/*                                                                        */
/**************************************************************************/
int main(int argc, char *argv[])
{
	int ret;

	uint32_t parhandle;	/* handle of parent key */
	unsigned char hashpass1[20];	/* hash of new key password */
	unsigned char hashpass2[20];	/* hash of migration password */
	unsigned char hashpass3[20];	/* hash of parent key password */
	unsigned char default_pass[8] = "SRK PWD";
	unsigned char default_hash[20];
	keydata k;		/* keydata structure for input key parameters */
	keydata q;		/* keydata structure for resulting key */
	RSA *rsa;		/* OpenSSL format Public Key */
	FILE *keyfile;		/* output file for public key */
	FILE *blbfile;		/* output file for encrypted blob */
	EVP_PKEY pkey;		/* OpenSSL public key */
	unsigned char filename[256]; /* file name string of public key file */
	unsigned char blob[4096];	/* area to hold key blob */
	unsigned int bloblen;	/* key blob length */
	unsigned char *keyname;	/* pointer to key name argument */
	unsigned char *aptr1 = NULL;
	unsigned char *aptr2 = NULL;
	unsigned char *aptr3 = NULL;
	int nxtarg;

	TPM_setlog(0);		/* turn on verbose output */

	/*
	 **  parse command line
	 */
	nxtarg = ParseArgs(argc, argv);
	if (argc < (nxtarg + 2))
		usage();
	keyname = argv[nxtarg + 0];

	/* OK, this is annoying. The IBM CSS standard for defaulted
         * passwords is "SRK PWD\0", which is then hashed before use.
  	 * TSS compatible libraries use an array of 20 zeros instead,
   	 * so we need to handle the IBM case specially.
         */
	TSS_sha1(default_pass, 8, default_hash);
	
	/*
	 ** convert parent key handle from hex
	 */
	ret = sscanf(argv[nxtarg + 1], "%x", &parhandle);
	if (ret != 1) {
		fprintf(stderr, "Invalid argument '%s'\n",
			argv[nxtarg + 1]);
		exit(2);
	} 

	/*
	 ** use the SHA1 hash as the Parent Key Authorization Data
	 */
	if (parpass != NULL) {
		TSS_sha1(parpass, strlen(parpass), hashpass1);
		aptr1 = hashpass1;
	} else if(ibm_default && (parhandle == 0x40000000))
		aptr1 = default_hash;
	/*
	 ** use the SHA1 hash as the Key Authorization Data
	 */
	if (keypass != NULL) {
		TSS_sha1(keypass, strlen(keypass), hashpass2);
		aptr2 = hashpass2;
	} 

	/*
	 ** use the SHA1 hash as the Key Migration Authorization Data
	 */
	if (migpass != NULL) {
		TSS_sha1(migpass, strlen(migpass), hashpass3);
		aptr3 = hashpass3;
	}

	/*
	 ** initialize new key parameters
	 */
	k.keyflags = 0;
	if (migpass != NULL)
		k.keyflags |= 0x00000002;	/* key flags - migratable */
	if (keypass != NULL)
		k.authdatausage = 1;	/* key requires authorization ) */
	else
		k.authdatausage = 0;	/* key requires no authorization */
	k.privkeylen = 0;	/* no private key specified here */
	k.pub.algorithm = 0x00000001;	/* key algorithm 1 = RSA */
	if (keytype == 's') {
		k.keyusage = 0x0010;	/* key Usage - 0x0010 = signing */
		k.pub.encscheme = 0x0001;
		k.pub.sigscheme = 0x0002;	/* signature scheme RSA/SHA1  */
	} else if (keytype == 'e') {
		k.keyusage = 0x0011;	/* key Usage - 0x0011 = encryption */
		k.pub.encscheme = 0x0003;	/* encryption scheme 3 RSA */
		k.pub.sigscheme = 0x0001;	/* signature scheme NONE  */
	} else if (keytype == 'b') {
		k.keyusage = 0x0014;	/* key Usage - 0x0014 = bind */
		k.pub.encscheme = 0x0003;	/* encryption scheme 3 RSA */
		k.pub.sigscheme = 0x0001;	/* signature scheme none */
	} else if (keytype == 'l') {
		k.keyusage = 0x0015;	/* key Usage - 0x0015 = legacy */
		k.pub.encscheme = 0x0003;	/* encryption scheme 3 RSA */
		k.pub.sigscheme = 0x0002;	/* signature scheme RSA/SHA1  */
	} else
		usage();
	k.pub.keybitlen = 2048;	/* RSA modulus size 2048 bits */
	k.pub.numprimes = 2;	/* required */
	k.pub.expsize = 0;	/* RSA exponent - default 0x010001 */
	k.pub.keylength = 0;	/* key not specified here */
	k.pub.pcrinfolen = 0;	/* no PCR's used at this time */

	/*
	 ** create and wrap an asymmetric key and get back the
	 ** resulting keydata structure with the public and encrypted
	 ** private keys filled in by the TPM
	 */
	ret =
	    TPM_CreateWrapKey(parhandle, aptr1, aptr2, aptr3, &k, &q, blob,
			      &bloblen);
	if (ret != 0) {
		fprintf(stderr, "Error %s from TPM_CreateKey\n",
			TPM_GetErrMsg(ret));
		exit(3);
	}
	sprintf(filename, "%s.key", keyname);
	blbfile = fopen(filename, "w");
	if (blbfile == NULL) {
		fprintf(stderr, "Unable to create key file\n");
		exit(5);
	}
	ret = fwrite(blob, 1, bloblen, blbfile);
	if (ret != bloblen) {
		fprintf(stderr, "I/O Error writing key file\n");
		exit(6);
	}
	fclose(blbfile);
	/*
	 ** convert the returned public key to OpenSSL format and
	 ** export it to a file
	 */
	rsa = TSS_convpubkey(&(q.pub));
	if (rsa == NULL) {
		fprintf(stderr, "Error from TSS_convpubkey\n");
		exit(5);
	}
	OpenSSL_add_all_algorithms();
	sprintf(filename, "%s.pem", keyname);
	EVP_PKEY_assign_RSA(&pkey, rsa);
	keyfile = fopen(filename, "w");
	if (keyfile == NULL) {
		fprintf(stderr, "Unable to create public key file\n");
		exit(6);
	}
	ret = PEM_write_PUBKEY(keyfile, &pkey);
	if (ret == 0) {
		fprintf(stderr, "I/O Error writing public key file\n");
		exit(7);
	}
	fclose(keyfile);
	RSA_free(rsa);
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
		case 't':
			if (*optarg == '-') {
				fprintf(stderr,
					"option -t missing an argument\n");
				usage();
			}
			if (optarg[0] != 's' && optarg[0] != 'e' &&
			    optarg[0] != 'b' && optarg[0] != 'l')
				usage();
			keytype = optarg[0];
			break;
		case 'm':
			if (*optarg == '-') {
				fprintf(stderr,
					"option -m missing an argument\n");
				usage();
			}
			migpass = optarg;
			break;
		case 'p':
			if (*optarg == '-') {
				fprintf(stderr,
					"option -p missing an argument\n");
				usage();
			}
			parpass = optarg;
			break;
		case 'k':
			if (*optarg == '-') {
				fprintf(stderr,
					"option -k missing an argument\n");
				usage();
			}
			keypass = optarg;
			break;
		case 'i':

			ibm_default=1;
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
		"Usage: createkey [<options>] <keyname> <pkeyhandle>\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "   Where the arguments are...\n");
	fprintf(stderr, "    <keyname>    is the new key name\n");
	fprintf(stderr,
		"    <pkeyhandle> is the parent key handle in hex\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "   Where the <options> are...\n");
	fprintf(stderr,
		"    -t s | e | b | l  keytype is s for signing, e for encryption(storage)\n");
	fprintf(stderr,
		"                                 b for binding, l for legacy\n");
	fprintf(stderr,
		"    -p <parpass>      to specify parent key use password\n");
	fprintf(stderr,
		"    -k <keypass>      to specify new key use password\n");
	fprintf(stderr,
		"    -m <migpass>      to specify new key is migratable, and specify migration password\n");
	fprintf(stderr, "    -i		       to use IBM CSS default passwords\n");
	fprintf(stderr,
		"    -?                print usage information (this message)\n");
	exit(1);
}
