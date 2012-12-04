/*
 * loadkernkey [tpm key directory]
 *               get kernel master key, and load it into root's keyring.
 *               This is run from initrd's nash script and must be
 *               statically linked. The TPM sealed secret key
 *               is normally stored on in /etc/bootkeys with two files:
 *                    syspcr.key (the sealing key to be loaded under SRK)
 *                    kmk.sealed (the file to be unsealed)
 *               If these keys do not exist, a password 
 *               is requested from the console, and used instead.
 *
 * Copyright (C) 2005 IBM Corporation
 * Authors: David Safford <safford@watson.ibm.com>
 *
 *      This program is free software; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 2 of the License, or
 *      (at your option) any later version.
 *
 */
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <sys/reboot.h>
#include <netinet/in.h>
#include <asm/unistd.h>
#include <stdint.h>
#include <tpmfunc.h>
#include <tpmutil.h>
#include <tpmkeys.h>

#define TPM_SRK_HANDLE 0x40000000
#define PCR_MASK (15)
#define KEY_SPEC_USER_KEYRING -4 
#define TPMKEY "evm_key"
#define TPMKEYSIZE 20
#define KEYDIR "/etc/bootkeys"
#define SYSPCR_FILE "syspcr.key"
#define SEAL_FILE "kmk.sealed"

/* IBM CSS compatibility */
#define SRKPASS "SRK PWD"

static unsigned long add_tpm_key(unsigned long len, unsigned char *buf);
static void loadpass(char *pass, int passlen);
static int unseal_secret(unsigned char *syspcr, int slen,
			 unsigned char *seal, int klen);
static int get_files(char *dir,unsigned char *syspcr, int *slen,
                     unsigned char *seal, int *klen);
static void load_failed(void);
static void loadfrompass(void);
static void mygetline(int fd, char *p,int *l, int echo);

int main(int argc, char *argv[])
{
	unsigned char sealed[1024], syspcr[1024];
	char *defdir;
	int ret, klen=0, slen=0;

	if(argc==2)
		defdir=argv[1];
	else 
		defdir=KEYDIR;

	if((ret = get_files(defdir,syspcr,&slen,sealed,&klen)) < 0)
		loadfrompass();
	else if((ret = unseal_secret(syspcr,slen,sealed,klen)) != 0){
			printf("Failed to load kernel master key\n");
			load_failed();
	}

	exit(0);
}

static int get_files(char *dir,unsigned char *syspcr, int *slen,
                     unsigned char *sealed, int *klen)
{
	char sfile[256], bfile[256];
	int fd,ret;

	sprintf(sfile,"%s/%s",dir,SYSPCR_FILE);
	sprintf(bfile,"%s/%s",dir,SEAL_FILE);
	if((fd = open(sfile,O_RDONLY))<0)
		return(-1);
	if((ret = read(fd,syspcr,1024))<=0)
		return(-1);
	*slen = ret;

	if((fd = open(bfile,O_RDONLY))<0)
		return(-1);
	if((ret = read(fd,sealed,1024))<=0)
		return(-1);
	*klen = ret;
	return(0);
}

static void load_failed(void)
{
#ifndef USERTEST
	reboot(RB_HALT_SYSTEM);
#else
	exit(-1);
#endif
}

static int console_getpass(char *pass,int *plen);

#define MAXPASS 256
static void loadfrompass(void) 
{
	char pass[MAXPASS];
	int passlen=0;

	console_getpass(pass, &passlen);
	loadpass(pass,passlen);
}

/* read in line with or without echo. May be on console... */
static void mygetline(int fd, char *p,int *l, int echo)
{
	int i=0,j, res=1;
	struct termios old, new;

	if(!echo){
		res = ioctl(fd,TCGETS,&old);
       	 	if(!res){
			new=old;
			new.c_lflag &= ~(ECHO|ISIG|ICANON);
			res = ioctl(fd,TCSETS,&new);
		}
	}

	for(;;){
		if(read(fd,p+i,1)==1){
			if(i>=MAXPASS)
				break;
			if(p[i]=='\n'){
				if(!echo)
					write(1,"\n",1);
				break;
			}
			if(p[i]==0x7f || p[i]=='\b'){
				if(!echo)
					write(1,"\b \b",3);
				if(i>0)
					for(j=i-1;j<*l;j++)
						p[j]=p[j+2];
				i--;
				continue;
			}
			if(!echo)
				write(1,"*",1);	
			i++;
		}
	}
	*l = i;
	p[i]='\0';
	if(!echo)
		res = ioctl(fd,TCSETS,&old);
}

static int console_getpass(char *pass, int *plen)
{
	int fd=0;

	#ifndef USERTEST
	if ((fd = open("/dev/console", O_RDWR)) < 0) {
		printf("ERROR opening /dev/console!: %d\n", errno);
		return(-1);
	}
	#endif

	write(fd,"Enter Integrity Password: ",26);
	mygetline(fd,pass,plen,0);
	return(0);
}

static int32_t add_key(const char *type,
                 const char *description,
                 const void *payload,
                 size_t plen,
                 int32_t ringid)
{
        return syscall(__NR_add_key,
                       type, description, payload, plen, ringid);
}

unsigned long add_tpm_key(unsigned long len, unsigned char *buf)
{
	return(add_key("user",TPMKEY,buf,len,KEY_SPEC_USER_KEYRING));
}

int unseal_secret(unsigned char *syspcr,int syslen,
                         unsigned char *seal, int seallen)
{
        unsigned char auth[20];
        unsigned char srkhash[20];
        unsigned char kmk[TPMKEYSIZE];
        unsigned int kmklen;
        unsigned int ret, new_handle;
        keydata k;

        #ifdef USERTEST
                TPM_setlog(1);
        #else
                TPM_setlog(0);
        #endif

        TSS_KeyExtract(syspcr,&k);
	TSS_sha1((unsigned char *)SRKPASS,8,srkhash);
        ret = TPM_LoadKey(TPM_SRK_HANDLE,srkhash,&k,&new_handle);
        if(ret){
                printf("TPM_LoadKey failed, code %d\n",ret);
                return(-1);
        }
        memset(auth,0,sizeof(auth));
        ret = TPM_Unseal(new_handle,auth,auth,seal,seallen,kmk,&kmklen);
        if(ret){
                printf("TPM_Unseal failed, code %d\n",ret);
        	TPM_EvictKey(new_handle);
		return(-1);
        }
        /* load kmk into root's keyring, then burn this copy */
        add_tpm_key((unsigned long)kmklen,kmk);
        memset(kmk,0,TPMKEYSIZE);
        TPM_EvictKey(new_handle);

        #ifndef USERTEST
                /* extend PCR so unseal no longer possible */
                TSS_gennonce(auth);
                TPM_Extend(PCR_MASK,auth);
        #endif

        return(0);
}

void loadpass(char *pass, int passlen)
{
        add_tpm_key((unsigned long)passlen,(unsigned char *)pass);
}

