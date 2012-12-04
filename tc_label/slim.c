/*
 *	Read in a slim configuration file
 *
 * Copyright (C) 2005 IBM Corporation
 * Author: Mimi Zohar <zohar@us.ibm.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fnmatch.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <attr/xattr.h>
#include "slim.h"

static struct path *paths = NULL, *last_path = NULL, *end_path = NULL;
static int num_paths = 10;
int slim_debug = 0;

static int slm_comp_path(const void *, const void *);
static int slm_insert_path(char *, int);
static int slm_parse_config(char *);

/* Sort paths in descending order */
static int slm_comp_path(const void *p1, const void *p2)
{
	struct path *path1 = (struct path *) p1;
	struct path *path2 = (struct path *) p2;
	int rc;

	rc = strncmp(path2->fname, path1->fname,
		     path1->len > path2->len ? path1->len : path2->len);
	return (rc);
}

static int slm_insert_path(char *line, int len)
{
	char *fname = line;
	char *levels;
	int fname_len = 0;
	int i;

	while ((fname[fname_len] != '\0')
	       && (fname[fname_len] != '\n')
	       && ((fname[fname_len] != ' ') && (fname[fname_len-1] != '\\'))) 
		fname_len++;
	if (last_path == end_path) {
		if (! (paths = realloc(paths,
			     sizeof(struct path) * num_paths * 2))) {
			printf("slm_init_config: no memory\n");
			return (-1);
		}
		last_path = paths + num_paths;
		end_path = paths + (num_paths * 2);
		num_paths = num_paths * 2;
	}
	last_path->len = fname_len;

	last_path->fname = (char *) malloc(last_path->len + 1);
	memset(last_path->fname, 0, last_path->len + 1);
	strncpy(last_path->fname, fname, last_path->len);

	levels = fname + fname_len +1;
	while ((*levels == 0x0) || (*levels == 0xa))
		levels++;

	last_path->level_len = (line + len) - levels;
	last_path->levels = (char *) malloc(last_path->level_len + 1);
	memset(last_path->levels, 0, last_path->level_len + 1);
	memcpy(last_path->levels, levels, last_path->level_len);
	if (slim_debug) {
		printf("path_len %d path %s level_len %d ",
		       last_path->len, last_path->fname,
		       last_path->level_len);
		for (i = 0; i < last_path->level_len; i++)
			printf("%c", *(last_path->levels + i));
		printf("\n");
	}
	last_path++;
	return 0;
}

char *slm_lookup_path(const char *filepath)
{
	struct path *cur_path = paths;

	while (cur_path < last_path) {
		if (fnmatch(cur_path->fname, filepath, 0) == 0)
			return (cur_path->levels);
		cur_path++;
	}
	if (slim_debug)
		printf("slm_lookup_path: %s not found\n", filepath);
	return NULL;
}

void slm_print_paths(struct path *paths)
{
	struct path *cur_path = paths;

	while (cur_path < last_path) {
		printf("path: level= %s len= %d %s \n", cur_path->levels,
		       cur_path->len, cur_path->fname);
		cur_path++;
	}
}

static int slm_parse_config(char *fname)
{
	FILE *fd;
	char line[4096], *line_cur = line, *line_end = line;
	int size, comment = 0;

	if (!(fd = fopen(fname, "r"))) {
		perror("fopen: ");
		return (-1);
	}

	line_end += sizeof(line);
	memset(line, 0, sizeof line);
	while ((size = fread(line_cur, 1, 1, fd) != 0)
	       && (line_cur < line_end)) {
		if (*line_cur == 0x23) {
			comment++;
			line_cur++;
			continue;
		}
		if (*line_cur == 0x09) {
			*line_cur = 0x20;
			line_cur++;
			continue;
		}

		if (*line_cur == 0x0a) {
			*line_cur = 0x0;
			if (comment) {
				comment = 0;
			} else
			    if (slm_insert_path(line, line_cur - line) < 0) {
				fclose(fd);
				return (-1);
			}
			line_cur = line;
			memset(line, 0, sizeof(line));
		} else
			line_cur++;
	}
	fclose(fd);
	return 0;
}

void slm_cleanup_config()
{
	if (slim_debug)
		printf("slm: slm_cleanup_config\n");
	if (paths) {
		free(paths);
		num_paths = 10;
		paths = end_path = last_path = NULL;
	}
}

int slm_init_config(char *fname)
{
	int error = -1;
	char default_fname[] = "/etc/slim.conf";

	if (!fname)
		fname = default_fname;
	if (slim_debug)
		printf("slm: using config file %s\n", fname);

	if (!(paths = malloc(sizeof(struct path) * num_paths))) {
		printf("slm_init_config: no memory\n");
		return error;
	}
	last_path = paths;
	end_path = paths + num_paths;
	if (slm_parse_config(fname) < 0)
		return error;

	qsort(paths, last_path - paths, sizeof(struct path),
	      &slm_comp_path);
	if (slim_debug)
		slm_print_paths(paths);
	return 0;
}
