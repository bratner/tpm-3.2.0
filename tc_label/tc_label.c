/*
 *  tc_label - program to set slim and evm xattrs
 *
 *  tc_label clean [path]  (remove all slim/evm labels)
 *  tc_label verify [rpm pkg name]  (verify labels from RPM database)
 *  tc_label fixup [-s] [path] (fixup all files with level and hmac)
 *  tc_label promote [-s] <path> <level> [MUTABLE] (set xattr on one file)
 *
 * Copyright (C) 2005 IBM Corporation
 * Author: David Safford <safford@watson.ibm.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 */

/*
 * Symbolic links can be very confusing when dealing with evm
 * and slim extended attributes. On one hand, the security.evm.hash 
 * and security.evm.mutable attributes really apply only to the 
 * target, not the symbolic link, and when thinking about SYSTEM
 * and guard programs, we are largely concerned with the 
 * security.slim.level attribute of the target, not the link.
 * On the other hand, we do want to protect the symbolic link
 * itself from abuse, so we want some security.slim.level 
 * attribute on it, but it need not be the same as the target,
 * particularly for guard programs.
 * In addition, while the rpm database has separate entries
 * for the link and the target, and provides hashes only for
 * the target, it is more convenient for the user, and for the
 * /etc/slim.conf files to be able to name the convenience link,
 * and have tc_label figure out the right thing to do for both
 * the link and the target. In general this means that tc_label,
 * when given a link should:
 *    - apply the level to both the link and target
 *    - apply a hash (if any) to the target
 *    - apply the mutable flag (if any) to the target
 * tc_label has four operating modes:
 *    - clean      - remove from link only, as target will also be done.
 *    - initialize - do link only as rpm has both target and link in DB.
 *    - fixup      - do link only, as target will also be visited.
 *                   do not apply hash or mutable (will be added to conf)
 *                   so that we don't accidentally mutable a log file...
 *    - promote    - apply best guess logic above.
 *                   user must manually request hash/mutable
 * If the administrator wants distict level rules for the link and
 * target, this can always be indicated with a rule for the link
 * first, and a rule for the target second.
 * EVM allows files not to have hashes, in which case only the 
 * level attribute is HMAC'ed. This is useful for things like
 * log files, which are constantly changing, and for which 
 * protection against off-line attack is not important. Changing
 * files, such as configuration files, which change less frequently,
 * and which are security sensitive, can have MUTABLE hashes,
 * which are automatically updated upon changes.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <openssl/md5.h>
#include <errno.h>
#include <attr/xattr.h>
#include <netinet/in.h>
#include <time.h>
#include "slim.h"

#define CONFIG_FILE "/etc/slim.conf"

int promote(uid_t uid, int argc, char *argv[]);
int rpm_pkg_verify(char *pkg);
int file_clean(char *path);
int file_start(char *path);
int file_walk(char *path);
static time_t now;
static int slimonly = 0;

int main(int argc, char *argv[])
{
	FILE *fp;
	char buf[1024];
	char fname[128];
	int fd, rc;
	uid_t uid;
	size_t len;

	if((argc<2) || (argc>5)
	   || (strcmp(argv[1],"verify") 
	       && strcmp(argv[1],"fixup")
	       && strcmp(argv[1],"clean")
               && strcmp(argv[1],"promote"))){
		printf("usage: tc_label fixup [-s] [path]\n"
		       "       tc_label clean [path]\n"
		       "       tc_label promote [-s] path level [FIXED]\n"
		       "       tc_label verify [rpm package name]\n");
		return(-1); 
	}

	/* users can verify against rpm database */
	if(argc==2 && !strcmp(argv[1],"verify")){
		rpm_pkg_verify("-a");
		exit(0);
	}

	if(argc==3 && !strcmp(argv[1],"verify")){
		rpm_pkg_verify(argv[2]);
		exit(0);
	}

        if(argc==2 && !strcmp(argv[1],"clean")){
                file_clean("/");
                exit(0);
        }

        if(argc==3 && !strcmp(argv[1],"clean")){
                file_clean(argv[2]);
                exit(0);
        }

	if(argc>=3 && (!strcmp(argv[1],"fixup")||!strcmp(argv[1],"promote"))
		&& !strcmp(argv[2],"-s"))
		slimonly = 1;
	else {
		/* fixup and promote require evm to update hmac */
		strcpy(fname,"/tmp/tc_labelXXXXXX");
		fd=mkstemp(fname);
		if(fd!=-1){
			write(fd,buf,sizeof(buf));
			close(fd);
			rc=getxattr(fname,"security.evm.hmac",buf,sizeof(buf));
			if(rc==-1 && errno == ENOATTR)	
				printf("tc_label: warning - evm must be loaded and configured\n");
		}
	}
	
	uid = getuid();
        now = htonl(time(0));

	/* users can promote/demote up to USER level */
	if(argc>2 && !strcmp(argv[1],"promote")){
		promote(uid,argc,argv);
		exit(0);
	}

	/* fixup requires root/SYSTEM */
	if(uid){
		printf("Must be root to do %s\n",argv[1]);
		exit(-1);
	}
        fp=fopen("/proc/self/attr/current","r");
        if(fp){
                memset(buf,0,sizeof(buf));
                len = fread(buf,1,sizeof(buf),fp);
                if(strncmp(buf+9,"SYSTEM",6)){
                        printf("Must be SYSTEM guard level: was %s\n",buf);
			fflush(stdout);
                        exit(-1);
		}
                fclose(fp);
        }

	if(argc>=2 && !strcmp(argv[1],"fixup")){
		if(argc==2)
			file_start("/");
		else if(argc==3 && slimonly)
			file_start("/");
		else if(argc==3 && !slimonly)
			file_start(argv[2]);
		else if(argc==4)
			file_start(argv[3]);
	}

	return(0);
}

/* Convert memory to a hex string */
void mem2hex(unsigned char *mem, char *buffer, int count)
{
        const char hexchars[] = "0123456789abcdef";
        int i;
        char *buf = buffer;
        int ch;

        memset(buffer, 0, count);
        for (i = 0; i < count; i++) {
                ch = (int) *mem++;
                *buf++ = hexchars[(ch >> 4) & 0xf];
                *buf++ = hexchars[ch & 0xf];
        }
}

/* calculate file hash */
int MD5_calc(char *fname, unsigned char *result)
{
        char rbuf[1024 * 1024];
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
        	MD5_Final(result, &c);
	} else {
		/* for regular file, hash data */
        	if ((fd = open(fname, O_RDONLY, 0)) < 0) {
               		perror("open:");
                	return fd;
        	}
        	memset(rbuf, 0, sizeof rbuf);
        	MD5_Init(&c);
        	while ((buf_len = read(fd, rbuf, sizeof rbuf)) > 0)
                	MD5_Update(&c, rbuf, buf_len);
        	MD5_Final(result, &c);
        	close(fd);
	}
        return 0;
}
/* for all files in one RPM DB, verify hash and MUTABLE xattrs 
 * if symbolic link, verify just the link, not the target 
 */
int rpm_pkg_verify(char *pkg)
{
	FILE *fp;
	char *buf, *level;
	char query[1024],fname[1025],hash[34],config[2],value[1024];
	unsigned char bhash[34];
	int rc,s;
	size_t l=1024;
	struct stat64 fs;

	rc=slm_init_config(CONFIG_FILE);
  	if(rc){
		printf("Could not find config file %s\n",CONFIG_FILE);
		exit(-1);
	}
	/* get filename::hash::flags from rpm */
	snprintf(query,sizeof(query),"/bin/rpm -q --qf '[%%{FILENAMES}"
		"::%%{FILEMD5S}::%%{FILEFLAGS}\n]' %s",pkg);
	fp=popen(query,"r");
	buf = calloc(1,l);
	while(getline(&buf,&l,fp)>0){
		s=sscanf(buf,"%[^:\n]::%[^:\n]::%[^:\n] ",fname,hash,config); 
		printf("\n%s",fname);
		if(lstat64(fname,&fs)){
			printf("\n\tlstat failed");
			memset(buf,0,l);
			continue;
		}
		level = slm_lookup_path(fname);
   		if(level){
			printf("\n\tLevel conf %s ",level);
			rc = lgetxattr(fname, "security.slim.level", 
				value,sizeof(value));
			if((rc<0)&&(errno != ENOTSUP))
				printf("\n\tLevel xattr none ");	
			else
				printf("\n\tLevel xattr %s ", value+4); 
		} 
		if (s==3){
			/* have hash and config flag */
			rc = lgetxattr(fname, "security.evm.hash", 
				value, sizeof(value));
			if(rc<0)
				printf("\n\thash rpm    %s \n\thash xattr  "
					"none ",hash); 
			else
				printf("\n\thash rpm    %s \n\thash xattr  "
					"%s ",hash,value+4);

			MD5_calc(fname,bhash);
			memset(hash,0,sizeof(hash));
			mem2hex(bhash,hash,MD5_DIGEST_LENGTH);
			printf("\n\thash actual %s ",hash);

			rc = getxattr(fname, "security.evm.mutable",
				value, sizeof(value));
			if(rc>0)
				printf("\n\tmutable ");
			if(config[0]=='1'){
				printf("\n\tconfig ");
			}
		} 
		memset(buf,0,l);
	}
	printf("\n");
	return(0);
}

int file_start(char *path)
{
	int rc;

	rc=slm_init_config(CONFIG_FILE);
  	if(rc){
		printf("Could not find config file %s\n",CONFIG_FILE);
		exit(-1);
	}
	file_walk(path);
	exit(0);
}


/* walk and fixup: add level, mutable (if not executable), and hash
 * DO NOT label target, just the link, to prevent mischief
 */
int file_walk(char *path)
{
	struct stat64 fs;
	char pathname[1024];
	DIR *dir;
	struct dirent *dirent;
	char *f, *level;
	char ahash[1024];
	int isdir=0, isreg=0, islnk=0, issock=0, isx=0;
	unsigned char md5buf[MD5_DIGEST_LENGTH];
	int rc;

	/* see what type of file we have */
	if(lstat64(path,&fs)){
		printf("File %s not found\n",path);
		return(-1);
	}
	isdir=S_ISDIR(fs.st_mode);
	isreg=S_ISREG(fs.st_mode);
	islnk=S_ISLNK(fs.st_mode);
	issock=S_ISSOCK(fs.st_mode);
	isx=(fs.st_mode & S_IXUSR);

	if(!isdir && !isreg && !islnk && !issock)
		return(-1);

	level = slm_lookup_path(path);
   	if(level){
		rc = lsetxattr(path, "security.slim.level", level,
			strlen(level), 0); 
		if ((rc)&&(errno!=ENOTSUP)) 
			printf("set level failed for %s %s\n",
				path, level);
		if(rc)
			return(0);
	}

	if(!slimonly){
		/* calculate and set hash on reg or symlinks */
		if((isreg || islnk) && !issock){
			if(strncmp(level,"UNTRUSTED",9)){
				MD5_calc(path,md5buf);
				memset(ahash,0,sizeof(ahash));
				mem2hex(md5buf,ahash,MD5_DIGEST_LENGTH);
       				lsetxattr(path, "security.evm.hash", 
					ahash, strlen(ahash), 0);
				if(isreg && isx)
					lsetxattr(path,"security.evm.flags",
						"FIXED",5,0);
			} else {
				lremovexattr(path,"security.evm.hash");
				lsetxattr(path,"security.evm.flags",
					"UNHASHED",8,0);
			}
		}
	}

	/* if directory, recurse */
        if(isdir){
		/* skip sys, proc, dev */
		if(!strncmp(path,"/sys",4)
		   || !strncmp(path,"/proc",5)
                   || !strncmp(path,"/dev",4))
			return(0);	
		/* for each file in dir */
		dir = opendir(path);
		while((dirent=readdir(dir))){
			f = dirent->d_name;
			if(f[0]=='.' && f[1]=='\0')
				continue;
			if(f[0]=='.' && f[1]=='.' && f[2]=='\0')
				continue;
			if(!strcmp(path,"/"))
				snprintf(pathname,sizeof(pathname),
					"/%s",f);
			else
				snprintf(pathname,sizeof(pathname),
					"%s/%s",path,f);
			file_walk(pathname);
		}
		closedir(dir);
	}
	return(0);
}

/* label promote <file> <level> [FIXED] */
/* level label on both link and target, hash/mutable only to target */
int promote(uid_t uid, int argc, char *argv[])
{
	unsigned char md5buf[MD5_DIGEST_LENGTH];
	char value[256];
	struct stat64 fs;
	int rc, isdir;

	if(argc<4) {
		printf("tc_label promote <file> <level> [MUTABLE]\n");
		exit(-1);
	}
	/* check if file exists... */
	if(lstat64(argv[2+slimonly],&fs)){
		printf("File %s not found\n",argv[2+slimonly]);
		exit(-1);
	}

	/* set security.slim.level */
	/* make sure level value starts with space (historical reasons) */
	memset(value,0,sizeof(value));
	if(argv[3+slimonly][0] != ' ')
		snprintf(value,sizeof(value)-1,"%s",argv[3+slimonly]);
	rc = lsetxattr(argv[2+slimonly], "security.slim.level", 
		value, strlen(value), 0);
	rc |= setxattr(argv[2+slimonly], "security.slim.level", 
		value, strlen(value), 0);
	if (rc) {	
                printf("%s - ", argv[2+slimonly]);
                perror("[l]setxattr level: ");
	}
	/* if not root, that's all we can do... */
	if(uid)
		exit(0);

	/* if isdir, we're done */
	isdir=S_ISDIR(fs.st_mode);
	if(isdir)
		exit(0);

	if(!slimonly){
		if(strncmp(argv[3],"UNTRUSTED",9)){
			/* check/set security.evm.hash */
			MD5_calc(argv[2],md5buf);
			memset(value,0,sizeof(value));
			mem2hex(md5buf,value,MD5_DIGEST_LENGTH);
       			rc = setxattr(argv[2], "security.evm.hash", value,
				strlen(value), 0);
			if(rc) {
       				printf("%s - ", argv[2]);
       				perror("lsetxattr hash: ");
			}
		} else
        		lremovexattr(argv[2],"security.evm.hash");

		/* check-set security.evm.flags */
		if(argc==5){
			rc = setxattr(argv[2],"security.evm.flags",
				argv[4], strlen(argv[4]), 0);
			if(rc) {	
                		printf("%s - ", argv[2]);
               	 		perror("lsetxattr fixed: ");
			}
		} else
        		lremovexattr(argv[2],"security.evm.flags");

	} 

	exit(0);
}

int file_clean(char *path)
{
        struct stat64 fs;
        char pathname[1024];
        DIR *dir;
        struct dirent *dirent;
        char *f;
        int isdir=0, isreg=0, islnk=0;
        int rc;

        /* see what type of file we have */
        if(lstat64(path,&fs)){
                printf("File %s not found\n",path);
                return(-1);
        }
        isdir=S_ISDIR(fs.st_mode);
        isreg=S_ISREG(fs.st_mode);
        islnk=S_ISLNK(fs.st_mode);

        /* only check dirs.symlinks, and regular files */
        if(!isdir && !isreg && !islnk)
                return(0);

        /* remove any present xattrs */
        /* do this only on link, as target will also be visited...*/
        rc = lremovexattr(path,"security.slim.level");
        if(rc && (errno == ENOTSUP))
                return(0);
        lremovexattr(path,"security.evm.hash");
        lremovexattr(path,"security.evm.flags");
        lremovexattr(path,"security.evm.hmac");

        /* if directory, recurse */
        if(S_ISDIR(fs.st_mode)){
                /* for each file in dir */
                dir = opendir(path);
                while((dirent=readdir(dir))){
                        f = dirent->d_name;
                        if(f[0]=='.' && f[1]=='\0')
                                continue;
                        if(f[0]=='.' && f[1]=='.' && f[2]=='\0')
                                continue;
                        if(!strcmp(path,"/"))
                                snprintf(pathname,sizeof(pathname),
                                        "/%s",f);
                        else
                                snprintf(pathname,sizeof(pathname),
                                        "%s/%s",path,f);
                        file_clean(pathname);
                }
                closedir(dir);
        }
        return(0);
}
