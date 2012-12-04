/*
 * level.c - utility to display a process or file's level attribute
 *
 *     level [[-s] file...]
 *
 * Copyright (C) 2005 IBM Corporation
 * Author: David Safford <safford@watson.ibm.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <attr/xattr.h>
#include <time.h>
#include <sys/stat.h>
#include <unistd.h>
#include <rpm/rpmlib.h>
#include <rpm/rpmcli.h>
#include <rpm/rpmts.h>
#include <openssl/md5.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <libgen.h>

static void get_proc_level(void);
static void get_file_level(const char *filename, int slimonly);
static void MD5_calc_hex(const char *fname, char *hexbuf);
static void mem2hex(unsigned char *b, char *h, int count);

int main(int argc, char *argv[])
{
	int i,slimonly=0;
	if(argc==1)
		get_proc_level();
	else if(argc>1){
		if(!strcmp(argv[1],"-s"))
			slimonly=1;
		for(i=1+slimonly;i<argc;i++)
			get_file_level(argv[i],slimonly);
	}
	return(0);
}

static void get_proc_level(void)
{
	FILE *fp;
	char buf[1024];
	fp=fopen("/proc/self/attr/current","r");
	if(!fp){
		printf("MAC OFF\n");
		return;
	}
	memset(buf,0,sizeof(buf));
	fread(buf,1,1024,fp);
	printf("%s\n",buf);
}

static void get_file_level(const char *filename, int slimonly)
{
	struct stat64 fs;
	FILE *fp;
	char buf[1024],alink[1024],target[1024];
	char alevel[1024],ahash[1024],fhash[1024];
	char aflags[1024],rhash[1024],ahmac[1024];
	int lalevel=0,laflags=0,lahash=0,lahmac=0,lrhash=0;
	int isdir=0, isreg=0, islnk=0, issock=0;
	int r=0;
	
	/* see what type of file we have */
	if(lstat64(filename,&fs)){
		printf("File %s lstat errno %d\n",filename,errno);
		return;
	}
	
	isdir=S_ISDIR(fs.st_mode);
	isreg=S_ISREG(fs.st_mode);
	islnk=S_ISLNK(fs.st_mode);
	issock=S_ISSOCK(fs.st_mode);

	if(islnk){
		memset(alink,0,sizeof(alink));
		memset(target,0,sizeof(target));
		r = readlink(filename,alink,sizeof(alink));
		if(alink[0]!='/'){
			/* relative link - build full path */
			strncpy(buf,filename,sizeof(buf));
			snprintf(target,sizeof(target),"%s/%s",
				dirname((char *)buf),alink);	
		}else{
			/* absolute link */
			strncpy(target,alink,sizeof(target));
		}
	}

	/* only report on dirs, regular, link and socket files */
	if(!isdir && !isreg && !islnk && !issock){
		printf("Level: %s not a reportable file\n",filename);
		return;
	}

	/* get security.slim.level (value is timestamp+ascii)*/
	memset(alevel,0,sizeof(alevel));
	lalevel=lgetxattr(filename,"security.slim.level",alevel,sizeof(alevel));

	if(!slimonly){
		/* get security.evm.flags */
		memset(aflags,0,sizeof(aflags));
		laflags=lgetxattr(filename,"security.evm.flags",aflags,
			sizeof(aflags));

		/* get security.evm.hash (timestamp+ascii hex)*/
		memset(ahash,0,sizeof(ahash));
		lahash = lgetxattr(filename,"security.evm.hash",ahash,
			sizeof(ahash));

		/* get security.evm.hmac (no timestamp, in binary)*/
		memset(ahmac,0,sizeof(ahmac));
		lahmac = lgetxattr(filename,"security.evm.hmac",ahmac,
			sizeof(ahmac));

		/* If we have hash xattr, get hash of actual file data.
       	 	 * We want 32 char ascii hex 
       	 	 */
		if(lahash>0){
			memset(fhash,0,sizeof(fhash));
			MD5_calc_hex(filename,fhash);
			/* get rpm database hash value */
			sprintf(buf,"rpm -q -f %s --dump|awk "
				"'{if ($1==\"%s\") print $4}'", 
				filename, filename);
			fp=popen(buf,"r");
			memset(rhash,0,sizeof(rhash));
			lrhash=fread(rhash,1,sizeof(rhash),fp);
		}
	}

	/* display what we found */
	printf("%s",filename);
	if(islnk)
		printf(" (symbolic link -> %s)",target);
	if(r==-1)
		printf("(invalid target, or too many links)");
	printf("\n");

	if(lalevel>0){
		printf("\tsecurity.slim.level:  %s\n",alevel);
	} else
		printf("\tsecurity.slim.level:  none\n");
	if(!slimonly){
		if(lahmac>0)
			printf("\tsecurity.evm.hmac:    present\n");
		else
			printf("\tsecurity.evm.hmac:    not present\n");
		if(laflags>0)
			printf("\tsecurity.evm.flags:   %s\n",aflags);
		else
			printf("\tsecurity.evm.flags:   not present\n");

		if(isdir){
			if(lahash>0)
				printf("\tsecurity.evm.hash:    "
					"DIR_WITH_HASH\n");
			else
				printf("\tsecurity.evm.hash:    dir_no_hash\n");
		} else {
			if(lahash<=0)
				printf("\tsecurity.evm.hash:    no_hash\n");
			else {
				printf("\tsecurity.evm.hash:    %s\n",ahash);
				if(lrhash>0)
					printf("\trpm hash:             %s",
						rhash);
				else
					printf("\tNO_RPM_HASH\n");
				printf("\tcalculated md5:       %s\n",fhash);
			}
		}
	}
	if(islnk){
		r = stat64(filename,&fs);
		if(r!=-1 || errno!=ELOOP)
			get_file_level(target,slimonly);	
		else
			printf("%s (too many symbolic links)\n",target);
	}
}

static void MD5_calc_hex(const char *fname, char *hexbuf)
{
	char rbuf[100*1024];
	unsigned char hash[MD5_DIGEST_LENGTH];
	int buf_len;
	MD5_CTX c;
	struct stat64 fs;
	int fd;

        lstat64(fname,&fs);
        if(S_ISLNK(fs.st_mode)){
                /* for sym link, hash the target value */
                memset(rbuf, 0, sizeof rbuf);
                readlink(fname,rbuf,sizeof(rbuf));
                buf_len = strnlen(rbuf,sizeof(rbuf));
                MD5_Init(&c);
                MD5_Update(&c, rbuf, buf_len);
                MD5_Final(hash, &c);
        } else {
		if ((fd = open(fname, O_RDONLY, 0)) < 0) {
                	perror("open:");
                	exit(-1);
        	}
        	memset(rbuf, 0, sizeof rbuf);
        	MD5_Init(&c);
        	while ((buf_len = read(fd, rbuf, sizeof rbuf)) > 0)
                	MD5_Update(&c, rbuf, buf_len);
        	MD5_Final(hash, &c);
        	close(fd);
	}
	mem2hex(hash,hexbuf,MD5_DIGEST_LENGTH);
}

/* Convert memory to a hex string */
static void mem2hex(unsigned char *mem, char *buffer, int count) {
	const char hexchars[] = "0123456789abcdef";
	int i;
	char *buf = buffer;
	int ch;

        memset(buffer, 0, count);
        for (i = 0; i < count; i++) {
                ch = (int )*mem++;
                *buf++ = hexchars[(ch >> 4) & 0xf]; // convert high hex bits
                *buf++ = hexchars[ch & 0xf]; // convert low hex bits
        }
}

