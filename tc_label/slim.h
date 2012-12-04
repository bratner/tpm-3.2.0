/*
	slim.h
*/

extern int slim_debug;

struct path {
	char *fname;
	int len;
	char *levels;
	int level_len;
};

extern char *slm_lookup_path(const char *);
extern void slm_print_paths(struct path *);
extern int slm_init_config(char *);
extern void slm_cleanup_config();

// extern int t_lsetxattr(const char *, char *, const char *);
// extern int t_setxattr(const char *, char *, const char *);
