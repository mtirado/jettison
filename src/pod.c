/* (c) 2015 Michael R. Tirado -- GPLv3, GNU General Public License, version 3.
 * contact: mtirado418@gmail.com
 *
 * pod.c
 *
 * loads configuration file, and enacts options defined therein
 *
 * TODO need some way to tell if a pod is in use, so user does not
 * reconfigure over a running environment
 *
 * bugs: spaces / tabs after parameters may cause failure.
 *
 */
#define _GNU_SOURCE
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <errno.h>
#include <syslog.h>
#include <fcntl.h>
#include "pod.h"
#include "misc.h"
#include "util/seccomp_helper.h"
#include "eslib/eslib.h"

/*
 *  prevent these exact paths from being mounted without MS_RDONLY.
 *  you can mount writable directories after these locations.
 *  theres probably more paths i should add to this list.
 *  be extra careful when running root pods.
 */
static char *g_rdonly_dirs[] =
{
	"/test",
	"/etc",
	"/sbin",
	"/root",
	"/home",
	"/bin",
	"/lib",
	"/usr",
	"/usr/etc",
	"/usr/sbin",
	"/usr/bin",
	"/usr/lib",
	"/usr/libexec",
	"/usr/include",
	"/usr/local",
	"/usr/local/etc",
	"/usr/local/sbin",
	"/usr/local/bin",
	"/usr/local/lib",
	"/usr/local/libexec",
	"/usr/local/include",
	"/mnt",
	"/var",
	"/run"
};
#define RDONLY_COUNT (sizeof(g_rdonly_dirs) / sizeof(*g_rdonly_dirs))

/* files at or below these paths can not be mounted to a pod. */
static char *g_blacklist_paths[] =
{
	"/boot",
	"/proc",
	"/sys",
	POD_PATH
};
#define BLACKLIST_COUNT (sizeof(g_blacklist_paths) / sizeof(*g_blacklist_paths))

/* node flags */
#define NODE_HOME  1 /* node created using home option */
#define NODE_EMPTY 2 /* mounted on itself (dest/dest) instead of (src/dest) */

/* bind mount data */
struct path_node
{
	struct path_node *next;
	char src[MAX_SYSTEMPATH];
	char dest[MAX_SYSTEMPATH];
	unsigned long mntflags;
	unsigned long nodeflags;
	/* strlens, no null terminator */
	unsigned int srclen;
	unsigned int destlen;
};
struct path_node *g_mountpoints;

/* external variables from jettison.c
 * non-jettison.c C callers will have to define these.
 */
extern char g_pty_slavepath[MAX_SYSTEMPATH];
extern gid_t g_rgid;
extern uid_t g_ruid;
extern int g_tracecalls;

#define MAX_PARAM (MAX_SYSTEMPATH * 4)
char g_params[MAX_PARAM];

/* much globals */
unsigned int g_lineno;
size_t g_filesize;
char *g_filedata;
int g_allow_dev;
int g_firstpass;
unsigned int g_podflags;

char g_fcaps[NUM_OF_CAPS];
int g_syscalls[MAX_SYSCALLS];
int g_blkcalls[MAX_SYSCALLS];
unsigned int  g_syscall_idx;
unsigned int  g_blkcall_idx;
char g_chroot_path[MAX_SYSTEMPATH];

static int pod_load_config(char *data, size_t size);
static int pod_enact_option(unsigned int option, char *params, size_t size);

/*
 * This keyword array is in sync with the option enum in pod.h
 */
#define KWLEN  32 /* maximum string length */
static char keywords[KWCOUNT][KWLEN] =
{
	{ "rootpidns"	},  /* don't create a new pid namespace */
	{ "newnet"	},  /* create new network namespace TODO how to */
	{ "newpts"	},  /* creates a new /dev/pts instance */
	{ "noproc"	},  /* do not mount /proc */
	{ "slog"	},  /* pod wants to write to system log */
	/* podflags cutoff, don't actually use this... */
	{ "|||||||||||||" },
	{ "seccomp_allow" }, /* add a syscall to seccomp whitelist.
				if nothing is added, everything is allowed. */
	{ "seccomp_block" }, /* block syscall without sigkill if using --strict */
	{ "file"        },  /* bind mount file with options w,r,x,d,s */
	{ "home"	},  /* ^  -- but $HOME/file is rooted in /podhome  */

	/* TODO make configuration file read string instead of number, like seccomp does
	 * also add a switch to disable capabilities (always set NO_NEW_PRIVS) */
	{ "cap_bset"	},  /* allow file capability in bounding set */

};



/* if anything fails between pod_prepare or on pod_enter */
int pod_free()
{
	memset(g_chroot_path, 0, sizeof(g_chroot_path));
	if (g_filedata) {
		free(g_filedata);
		g_filedata = NULL;
	}
	return 0;
}



/*
 * load config file into memory,
 * call first pass of pod_load_config:
 * copies out chroot path, and pod flags
 * */
int pod_prepare(char *filepath, char *outpath, unsigned int *outflags)
{
	int r;
	unsigned int i;
	FILE *file;
	char *filename;
	char *pwline;
	char *pwuser;
	char buf[MAX_SYSTEMPATH];

	if (outpath == NULL || outflags == NULL)
		return -1;

	if (MAX_SYSTEMPATH < 256) {
		printf("MAX_SYSTEMPATH is too small (<256)\n");
		return -1;
	}

	g_allow_dev = 0;
	g_podflags = 0;
	g_firstpass = 1;
	g_filedata = NULL;
	g_mountpoints = NULL;
	memset(g_chroot_path, 0, sizeof(g_chroot_path));
	memset(g_fcaps, 0, sizeof(g_fcaps));
	g_syscall_idx = 0;
	g_blkcall_idx = 0;

	for (i = 0; i < MAX_SYSCALLS / sizeof(unsigned int); ++i)
	{
		g_syscalls[i] = -1;
		g_blkcalls[i] = -1;
	}
	file = fopen(filepath, "r");
	if (file == NULL) {
		printf("could not read pod configuration file: %s\n", filepath);
		return -1;
	}

	pwline = passwd_fetchline(g_ruid);
	if (pwline == NULL) {
		printf("passwd file error\n");
		return -1;
	}
	pwuser = passwd_getfield(pwline, PASSWD_USER);
	if (pwuser == NULL) {
		printf("could not find your username in passwd file\n");
		return -1;
	}

	filename = eslib_file_getname(filepath);
	if (filename == NULL) {
		printf("bad filename\n");
		return -1;
	}
	snprintf(g_chroot_path, MAX_SYSTEMPATH, "%s/%s/%s", POD_PATH, pwuser, filename);
	if (strnlen(g_chroot_path, MAX_SYSTEMPATH) >= MAX_SYSTEMPATH-100) {
		printf("chroot path too long: %s\n", g_chroot_path);
		fclose(file);
		return -1;
	}
	if (eslib_file_path_check(g_chroot_path)) {
		printf("bad chroot path\n");
		fclose(file);
		return -1;
	}
	printf("filename: %s\r\n", filename);
	printf("chroot path: %s\r\n", g_chroot_path);

	fseek(file, 0, SEEK_END);
	g_filesize = ftell(file);
	fseek(file, 0, SEEK_SET);

	g_filedata = (char *)malloc(g_filesize+1); /* + terminator */
	if (g_filedata == NULL) {
		printf("malloc error\n");
		fclose(file);
		return -1;
	}

	if (fread(g_filedata, 1, g_filesize, file) != g_filesize){
		fclose(file);
		pod_free();
		return -1;
	}
	fclose(file);
	g_filedata[g_filesize] = '\0';

	/* first pass, copy out flags and path */
	r = pod_load_config(g_filedata, g_filesize);
	if (r) {
		printf("pod_load_config error: on line %d\n", g_lineno);
		pod_free();
		return -1;
	}
	g_firstpass = 0;

	/* protect user owned pods directory */
	snprintf(buf, MAX_SYSTEMPATH, "%s/%s", POD_PATH, pwuser);
	setuid(g_ruid);
	if (chmod(buf, 0750)) {
		printf("chmod(%s): %s\n", buf, strerror(errno));
		pod_free();
		return -1;
	}
	setuid(0);
	*outflags = g_podflags;
	strncpy(outpath, g_chroot_path, MAX_SYSTEMPATH-1);
	outpath[MAX_SYSTEMPATH-1] = '\0';
	return 0;
}





/*
 * set up the pods envionment and chroot.
 */
int pod_enter()
{
	int r;
	char pathbuff[MAX_SYSTEMPATH];
	unsigned long flags = MS_NOSUID
			    | MS_NOEXEC
			    | MS_NODEV
			    | MS_RDONLY;
	/* proc cannot be mounted MS_UNBINDABLE (3.10) */

	if ((g_podflags & (1 << OPTION_NOPROC)) == 0) {
		memset(pathbuff, 0, sizeof(pathbuff));
		strncpy(pathbuff, g_chroot_path, sizeof(pathbuff)-7);
		strncat(pathbuff, "/proc", 5);
		mkdir(pathbuff, 0755);
		if (mount(0, pathbuff, "proc", flags, 0) < 0) {
			printf("couldn't mount proc(%s): %s\n",pathbuff,strerror(errno));
			goto err_free;
		}
	}

	/* do the actual pod configuration now */
	r = pod_load_config(g_filedata, g_filesize);
	if (r < 0) {
		printf("pod_load_config(2) error: %d on line %d\n", r, g_lineno);
		goto err_free;
	}
	/* we're done here */
	pod_free();
	return 0;

err_free:
	pod_free();
	return -1;
}



static int do_chroot_setup()
{
	char podhome[MAX_SYSTEMPATH];
	int r;
	int l = strnlen(POD_PATH, MAX_SYSTEMPATH);

	if (l >= MAX_SYSTEMPATH / 2 || l <= 1)
		return -1;
	if (strncmp(g_chroot_path, POD_PATH, l) != 0)
		return -1;

	setuid(g_ruid);
	setgid(g_rgid);
	r = eslib_file_exists(g_chroot_path);
	if (r == -1)
		return -1;
	if (r == 0) { /* did not exist */
		if (eslib_file_mkdirpath(g_chroot_path, 0755, 0)) {
			printf("couldn't mkdir(%s); %s\n",
					g_chroot_path, strerror(errno));
			return -1;
		}
	}
	else {  /* path exists */
		r = eslib_file_isdir(g_chroot_path);
		if (r == 0) {
			printf("chroot path(%s) is not a directory\n", g_chroot_path);
			return -1;
		}
		else if (r == -1)
			return -1;
	}
	snprintf(podhome, MAX_SYSTEMPATH, "%s/podhome", g_chroot_path);
	mkdir(podhome, 0750);
	if (chown(g_chroot_path, 0, 0)) {
		printf("chown %s failed\n", podhome);
		return -1;
	}
	setuid(0);
	setgid(0);
	return 0;
}


/*
 * get $HOME string from environment, could make this optional to read
 * from /etc/passwd instead of letting user set it from environment.
 */
extern char **environ;
char *gethome()
{
	char **env = environ;
	char *r;
	ino_t root_ino;
	ino_t file_ino;
	unsigned int len;
	if (env == NULL) {
		printf("no environ??\n");
		return NULL;
	}
	while(*env)
	{
		if (strncmp(*env, "HOME=", 5) == 0) {
			r = &(*env)[5];
			len = strnlen(r, MAX_SYSTEMPATH);
			if (len >= MAX_SYSTEMPATH || len == 0)
				return NULL;
			if (eslib_file_path_check(r))
				return NULL;
			root_ino = eslib_file_getino("/");
			file_ino = eslib_file_getino(r);
			if (root_ino == 0 || file_ino == 0) {
				return NULL;
			}
			if (root_ino == file_ino) {
				printf("home cannot be \"/\" (root inode)\n");
				return NULL;
			}
			if (chop_trailing(r, len+1, '/')) {
				return NULL;
			}
			return r;
		}
		++env;
	}
	printf("could not find $HOME environment variable\n");
	return NULL;
}

/* returns -1 on error
 * 1 if path starts with blacklisted path string
 * 0 no match
 */
static int check_blacklisted(char *path)
{
	unsigned int i, len;

	if (path == NULL)
		return -1;
	for (i = 0; i < BLACKLIST_COUNT; ++i)
	{
		len = strnlen(g_blacklist_paths[i], MAX_SYSTEMPATH);
		if (len >= MAX_SYSTEMPATH)
			return -1;
		if (strncmp(path, g_blacklist_paths[i], len) == 0) {
			return 1;
		}

	}
	return 0;
}

static int check_pathperms(char *path)
{
	char tmpath[MAX_SYSTEMPATH];
	char updir[MAX_SYSTEMPATH];
	struct stat st;

	memset(&st, 0, sizeof(st));
	if (stat(path, &st)) {
		goto esrch;
	}
	/* start at parent if not a dir */
	if (!S_ISDIR(st.st_mode)) {
		if (eslib_file_getparent(path, updir)) {
			goto esrch;
		}
		if (updir[0] == '/' && updir[1] == '\0') {
			return 0;
		}
	}
	else {
		strncpy(updir, path, MAX_SYSTEMPATH-1);
		updir[MAX_SYSTEMPATH-1] = '\0';
	}
	while(1)
	{
		memset(&st, 0, sizeof(st));
		if (stat(updir, &st)) {
			break;
		}
		/* other read and search bits required if not dir owner */
		if (st.st_uid != g_ruid) {
			if (!(st.st_mode & S_IXOTH)) {
				break;
			}
		}
		strncpy(tmpath, updir, MAX_SYSTEMPATH-1);
		tmpath[MAX_SYSTEMPATH-1] = '\0';
		if (eslib_file_getparent(tmpath, updir)) {
			break;
		}
		if (updir[0] == '/' && updir[1] == '\0') {
			return 0;
		}
	}

esrch:
	printf("could not find file: %s\n", path);
	return -1;
}

static int prep_bind(struct path_node *node)
{
	int isdir, r;
	char *src, *dest;

	if (node == NULL)
		return -1;

	/* create home paths as user */
	if (node->nodeflags & NODE_HOME) {
		setuid(g_ruid);
	}

	src = node->src;
	dest = node->dest;

	if (eslib_file_path_check(src) || eslib_file_path_check(dest))
		return -1;
	if (strncmp(dest, g_chroot_path, strnlen(g_chroot_path, MAX_SYSTEMPATH)))
		return -1; /* dest is not in pod root... */

	isdir = eslib_file_isdir(src);
	if (isdir == -1)
		return -1;

	printf("prep_bind(%s, %s)\n", src, dest);

	/* needs a file / directory to bind over */
	r = eslib_file_exists(dest);
	if (r == -1)
		return -1;
	if (r == 1) { /* file already exists */
		if (isdir == 1) {
			r = eslib_file_isdir(dest);
			if (r == 0) {
				logerror("bind destination not a directory: %s", dest);
				return -1;
			} else if (r == -1)
				return -1;
		}
	}
	else { /* did not exist */
		if (isdir == 1) {
			if (eslib_file_mkdirpath(dest, 0755, 0)  == -1) {
				logerror("pod_prepare bind, mkdir failed: %s", dest);
				return -1;
			}
		}
		else if (eslib_file_mkfile(dest, 0755, 0) == -1) {
			logerror("pod_prepare  bind, mkfile failed: %s", dest);
			return -1;
		}
	}

	if (node->nodeflags & NODE_HOME) {
		if (setuid(0)) {
			printf("setuid: %s\n", strerror(errno));
			return -1;
		}
	}
	return 0;
}

static int do_bind(struct path_node *node)
{
	if (node == NULL)
		return -1;
	if (node->nodeflags & NODE_EMPTY) {
		printf("do_empty(%s, %s)\n", node->src, node->dest);
		if (mount(node->dest, node->dest, NULL, MS_BIND, NULL)) {
			printf("home mount failed: %s\n", strerror(errno));
			return -1;
		}
	}
	else {
		printf("do_bind(%s, %s)\n", node->src, node->dest);
		if (mount(node->src, node->dest, NULL, MS_BIND, NULL)) {
			printf("mount failed: %s\n", strerror(errno));
			return -1;
		}
	}
	/* remount */
	if (mount(NULL, node->dest, NULL, MS_BIND|MS_REMOUNT|node->mntflags, NULL)) {
		printf("remount failed: %s\n", strerror(errno));
		return -1;
	}
	if (mount(NULL, node->dest, NULL, MS_SLAVE|MS_REC, NULL)) {
		printf("could not make slave: %s\n", strerror(errno));
		return -1;
	}
	return 0;
}



int create_pathnode(char *params, size_t size, int home)
{
	char src[MAX_SYSTEMPATH];
	char dest[MAX_SYSTEMPATH];
	char *path;
	char *homepath;
	struct path_node *node;
	uid_t fuid;
	unsigned int i, len;
	unsigned long remountflags;
	char c;

	if (params == NULL || size == 0)
		goto bad_param;

	if (strnlen(params, size) >= MAX_SYSTEMPATH) {
		printf("path too long\n");
		return -1;
	}

	remountflags =	  MS_REMOUNT
			| MS_NOEXEC
			| MS_RDONLY
			| MS_NOSUID
			| MS_NODEV
			| MS_UNBINDABLE;

	/* read mount permissions from parameters */
	for (i = 0; i < size; ++i)
	{
		c = params[i];
		if (c == ' ' || c == '\t') {
			++i;
			break;
		}
		if (i >= 5)
			goto bad_param;
		switch (c)
		{
			case 'r':
				break;
			case 'w':
				remountflags &= ~MS_RDONLY;
				break;
			case 'x':
				remountflags &= ~MS_NOEXEC;
				break;
			case 's':
#ifdef USE_FILE_CAPS
				remountflags &= ~MS_NOSUID;
#else
				printf("WARNING: ");
				printf("s parameter disabled\n");
#endif
				break;
			case 'd':
				remountflags &= ~MS_NODEV;
				break;
			default:
				goto bad_param;
		}
	}
	if (i >= size)
		return -1;

	/* get the path, must start with / */
	for (; i < size; ++i) {
		if (params[i] == '/')
			break;
		if (params[i] != ' ' && params[i] != '\t') {
			printf("bind path must start with /\n");
			return -1; /* not whitespace */
		}
	}
	if (i >= size)
		goto bad_param;

	path = &params[i];
	chop_trailing(path, MAX_SYSTEMPATH, '/');
	if (eslib_file_path_check(path))
		return -1;

	/* setup mount assuming / == /$HOME/user to be mounted in /podhome
	 * e.g. /.bashrc translates to POD_PATH/$USER/filename.pod/podhome/.bashrc
	 */
	if (home) {
		homepath = gethome();
		if (homepath == NULL)
			return -1;
		if (check_blacklisted(homepath)) {
			printf("$HOME is blacklisted: %s\n", homepath);
			return -1;
		}
		if (eslib_file_isdir(homepath) != 1) {
			printf("$HOME is not a directory: %s\n", homepath);
			return -1;
		}
		fuid = eslib_file_getuid(homepath);
		if (fuid == (uid_t)-1)
			return -1;
		if (fuid != g_ruid) {
			printf("$HOME permission denied: %s\n", homepath);
			return -1;
		}
		snprintf(src,  MAX_SYSTEMPATH-1, "%s%s", homepath, path);
		snprintf(dest, MAX_SYSTEMPATH-1, "%s/podhome%s", g_chroot_path, path);
	}
	else { /* setup mount normally */
		strncpy(src , path, MAX_SYSTEMPATH-1);
		if (check_blacklisted(src)) {
			return -1;
		}
		snprintf(dest, MAX_SYSTEMPATH-1, "%s%s", g_chroot_path, src);
	}
	src[MAX_SYSTEMPATH-1]  = '\0';
	dest[MAX_SYSTEMPATH-1] = '\0';

	/* make sure path is visible to our ruid */
	if (check_pathperms(src)) {
		return -1;
	}

	/* create the new node */
	node = malloc(sizeof(*node));
	if (node == NULL)
		return -1;
	memset(node, 0, sizeof(*node));

	/* setup source */
	len = strnlen(src, MAX_SYSTEMPATH);
	if (len >= MAX_SYSTEMPATH)
		return -1;
	strncpy(node->src, src, len);
	node->src[len] = '\0';
	node->srclen = len;

	/* dest */
	len = strnlen(dest, MAX_SYSTEMPATH);
	if (len >= MAX_SYSTEMPATH)
		return -1;
	strncpy(node->dest, dest, len);
	node->dest[len] = '\0';
	node->destlen = len;

	if (home) {
		node->nodeflags |= NODE_HOME;
	}
	node->mntflags = remountflags;
	node->next = g_mountpoints;
	g_mountpoints = node;

	return 0;

bad_param:
	printf("bad file param, missing rwxsd value(s) \n");
	return -1;
}

/*
 * return -1 on error,
 * 1 if any path_nodes start with path
 * 0 if could not match beginning of any path_node with path
 */
static int match_pathnode(char *path)
{
	struct path_node *n = g_mountpoints;
	unsigned int len;

	if (path == NULL)
		return -1;

	len = strnlen(path, MAX_SYSTEMPATH);
	if (len >= MAX_SYSTEMPATH)
		return -1;

	while (n)
	{
		if (strncmp(path, n->src, len) == 0)
			return 1;
		n = n->next;
	}
	return 0;
}

/* return exact matching node,
 * return NULL on error,
 * ENOENT if not found
 * ENOTUNIQ if multiples found
 */
static struct path_node *get_pathnode(char *path)
{
	struct path_node *n = g_mountpoints;
	struct path_node *ret = NULL;
	unsigned int len;

	if (path == NULL)
		return NULL;

	errno = 0;
	len = strnlen(path, MAX_SYSTEMPATH);
	if (len >= MAX_SYSTEMPATH)
		return NULL;

	while (n)
	{
		if (strncmp(path, n->src, len) == 0
				&& n->src[len] == '\0') {
			if (ret) {
				printf("duplicate entries\n");
				errno = ENOTUNIQ;
				return NULL;
			}
			ret = n;
		}
		n = n->next;
	}
	if (ret == NULL)
		errno = ENOENT;
	return ret;
}

/* sort mountpoints by length
 *
 * sort paths shortest to longest and check for duplicate entries.
 * sorting enables predictable hierarchical bind order
 * e.g. /usr always gets mounted before /usr/lib
 *
 * TODO
 * perhaps we should set rdonly paths as private instead of slave?
 */
static int prepare_mountpoints()
{
	struct path_node *a, *b, *tmp, *prev;
	unsigned int i, count;

	if (g_mountpoints == NULL)
		return -1;

	/* if we are mounting below or at a rdonly path, make sure there is a
	 * unique entry in g_mountpoints, and note which are empty directories
	 */
	for (i = 0; i < RDONLY_COUNT; ++i)
	{
		char opt[MAX_SYSTEMPATH];
		int r;

		/* find node that starts with rdonly path */
		r = match_pathnode(g_rdonly_dirs[i]);
		if (r == -1)
			return -1;
		else if (r == 0)
			continue;

		/* check if exact path already exists */
		tmp = get_pathnode(g_rdonly_dirs[i]);
		if (tmp == NULL && errno != ENOENT)
			return -1;
		if (tmp) {
			/* exists, override with rdonly flag */
			printf("override as rdonly: %s\n", tmp->src);
			tmp->mntflags |= MS_RDONLY;
			continue;
		}

		/* did not exist, we must create it before sorting */
		snprintf(opt, sizeof(opt), "r %s", g_rdonly_dirs[i]);
		if (create_pathnode(opt, sizeof(opt), 0)) {
			printf("couldn't create rdonly path(%s)\n", opt);
			return -1;
		}
		g_mountpoints->nodeflags |= NODE_EMPTY;
		printf("rdonly node marked as empty: %s\n", opt);
	}

	/* sort mountpoints in hierarchical order */
	count = 0;
	a = g_mountpoints;
	while (a)
	{
		a = a->next;
		++count;
	}
	for (i = 0; i < count; ++i )
	{
		prev = NULL;
		a = g_mountpoints;
		b = g_mountpoints->next;
		while (b)
		{
			if (a->srclen > b->srclen) {
				/* push a towards back */
				if (prev != NULL) {
					prev->next = b;
					a->next = b->next;
					b->next = a;
				}
				else {
					tmp = b->next;
					b->next = a;
					a->next = tmp;
					g_mountpoints = b;
				}
			}
			prev = a;
			a = b;
			b = b->next;
		}
	}

	/* check for duplicates */
	a = g_mountpoints;
	while (a)
	{
		b = a->next;
		while(b && b->srclen == a->srclen)
		{
			if (strncmp(a->src, b->src, a->srclen) == 0) {
				printf("error, duplicate entries: %s\n", a->src);
				return -1;
			}
			b = b->next;
		}
		a = a->next;
	}
	return 0;
}

/* returns negative on error,
 *  0 if ok,
 *  1 when first pass chroot was found
 *
 *  */
static int pod_enact_option(unsigned int option, char *params, size_t size)
{

	char src[MAX_SYSTEMPATH];
	char dest[MAX_SYSTEMPATH];
	char path[MAX_SYSTEMPATH];
	char syscall_buf[MAX_SYSCALL_DEFLEN];
	int  syscall_nr;
#ifdef USE_FILE_CAPS
	int  cap_nr;
	char cap_buf[MAX_CAP_DEFLEN];
#endif
	if (option >= KWCOUNT)
		return -1;

	/* first pass only cares about getting config flags, and path nodes */
	if (g_firstpass == 1) {
		if (option < OPTION_PODFLAG_CUTOFF) {
			/* set flag if below cutoff */
			g_podflags |= (1 << option);
		}
		/* file mount points need to be sorted after first pass */
		if (option == OPTION_FILE) {
			if (create_pathnode(params, size, 0)) {
				return -1;
			}
		}
		else if (option == OPTION_HOME) {
			if (create_pathnode(params, size, 1)) {
				return -1;
			}
		}
		return 0;
	}

	memset(src,  0, sizeof(src));
	memset(dest, 0, sizeof(dest));
	memset(path, 0, sizeof(path));

	switch (option)
	{

	/* caller is responsible for hooking these up */
	case OPTION_NEWNET:
	case OPTION_SLOG:
		break;

	/* give pod it's own pseudo terminal instance */
	case OPTION_NEWPTS:
		snprintf(dest, MAX_SYSTEMPATH, "%s/dev/pts", g_chroot_path);
		if (mkdir(dest, 0755) && errno != EEXIST)
			return -1;
		if (mount(0, dest, "devpts", 0, "newinstance") < 0)
			return -1;
		snprintf(src,  MAX_SYSTEMPATH, "%s/dev/pts/ptmx", g_chroot_path);
		if (chmod(src, 0666))
			return -1;
		snprintf(src,  MAX_SYSTEMPATH, "%s/dev/ptmx", g_chroot_path);
		printf("pts path: %s\n", src);
		if (symlink("pts/ptmx", src) && errno != EEXIST)
			return -1;
		break;

	/* add a systemcall to the whitelist */
	case OPTION_SECCOMP_ALLOW:
		if (params == NULL) {
			printf("null parameter\n");
			return -1;
		}
		if (g_syscall_idx >= MAX_SYSCALLS) {
			printf("too many syscalls in whitelist\n");
			return -1;
		}
		if (size >= MAX_SYSCALL_DEFLEN) {
			printf("seccomp_allow syscall name too long.\n");
			return -1;
		}
		memset(syscall_buf, 0, sizeof(syscall_buf));
		strncpy(syscall_buf, params, size);
		syscall_nr = syscall_getnum(syscall_buf);
		if (syscall_nr < 0) {
			printf("could not find syscall: %s\n", syscall_buf);
			return -1;
		}
		g_syscalls[g_syscall_idx] = syscall_nr;
		++g_syscall_idx;
		break;

	/* add a systemcall to the blocklist */
	case OPTION_SECCOMP_BLOCK:
		if (params == NULL) {
			printf("null parameter\n");
			return -1;
		}
		if (g_blkcall_idx >= MAX_SYSCALLS) {
			printf("too many syscalls in blocklist\n");
			return -1;
		}
		if (size >= MAX_SYSCALL_DEFLEN) {
			printf("seccomp_block syscall name too long.\n");
			return -1;
		}
		memset(syscall_buf, 0, sizeof(syscall_buf));
		strncpy(syscall_buf, params, size);
		syscall_nr = syscall_getnum(syscall_buf);
		if (syscall_nr < 0) {
			printf("could not find syscall: %s\n", syscall_buf);
			return -1;
		}
		g_blkcalls[g_blkcall_idx] = syscall_nr;
		++g_blkcall_idx;
		break;

	/* moved to end of second pass */
	case OPTION_FILE:
	case OPTION_HOME:
		break;

	/* change to bounding set */
	case OPTION_CAP_BSET:
#ifdef USE_FILE_CAPS
		if (params == NULL) {
			printf("null parameter\n");
			return -1;
		}

		memset(cap_buf, 0, sizeof(cap_buf));
		strncpy(cap_buf, params, size);
		cap_nr = cap_getnum(cap_buf);
		if (cap_nr < 0) {
			printf("could not find capability: %s\n", cap_buf);
			return -1;
		}
		if (cap_nr >= NUM_OF_CAPS) {
			printf("cap error\n");
			return -1;
		}
		printf("cap(%d) requested: %s\n", cap_nr, cap_buf);
		g_fcaps[cap_nr] = 1;
		break;
#else
		printf("file capabilities are disabled\n");
		return -1;
#endif

	default:
		printf("unknown option\n");
		return -1;
	}

	return 0;
}

static int find_keyword(char *kwcmp, size_t kwlen)
{
	int i = 0;
	if (kwlen >= KWLEN)
		return -1;

	for (; i < KWCOUNT; ++i)
	{
		if (strncmp(kwcmp, keywords[i], kwlen) == 0)
			return i;
	}
	return -1;
}


/* final stage of pass 1, add things to config as needed
 * depending on user supplied option
 */
static int pass1_finalize()
{
	char opt[MAX_SYSTEMPATH];

	/* whitelist jettison init program */
	snprintf(opt, sizeof(opt), "rx %s", INIT_PATH);
	if (create_pathnode(opt, sizeof(opt), 0)) {
		printf("couldn't create rdonly path(%s)\n", opt);
		return -1;
	}

	/* whitelist jettison preload */
	snprintf(opt, sizeof(opt), "rx %s", PRELOAD_PATH);
	if (create_pathnode(opt, sizeof(opt), 0)) {
		printf("couldn't create rdonly path(%s)\n", opt);
		return -1;
	}

	return 0;
}


#define STATE_NEWLINE  (1     ) /* on a fresh new line          */
#define STATE_COMMENT  (1 << 1) /* comment line                 */
#define STATE_KEYWORD  (1 << 2) /* validating keyword           */
#define STATE_SCAN     (1 << 3) /* scanning option parameters   */


/* returning non-zero is an error.
 *
 * Go through each line of configuration file, scanning for keyword and it's parameters.
 * Starts off in newline state, check for a valid keyword.
 * Read parameters of keyword, if any, and take appropriate action.
 *
 * STATE_NEWLINE - determine new state based on first character of new line.
 * STATE_COMENT  - seek to new line.
 * STATE_KEYWORD - read keyword, check validity and find start of parameters.
 * STATE_SCAN    - read parameters into buffer, call pod_enact_option
 *
 */
static int pod_load_config(char *data, size_t size)
{
	unsigned int state = STATE_NEWLINE;
	char *scan = data;
	char *eof  = data + size ; /* stay under this address */
	char  c;
	char  kwcmp[KWLEN];
	char *keystart;
	int   key = -1; /* index into keywords */
	size_t kwlen;
	char *scanstart;
	int r;

	scan = data;
	state = STATE_NEWLINE;
	g_lineno = 0;
	for(; scan < eof; ++scan)
	{
		switch(state)
		{

		/*
		 * on a new line, check if comment, or keyword.
		 * if whitespace, keep searching.
		 */
		case STATE_NEWLINE:
			++g_lineno;
			if (*scan == '#') /* comment */
				state = STATE_COMMENT;
			else if (*scan == '\n' || *scan == ' ' || *scan == '\t')
				continue; /* consecutive newlines are ok*/
			else
				state = STATE_KEYWORD;
		break;

		/* jump to next line */
		case STATE_COMMENT:
			for (; scan < eof; ++scan)
				if (*scan == '\n')
					break;

			if (scan >= eof)
				return -1;

			state = STATE_NEWLINE;
		break;

		/* match keyword */
		case STATE_KEYWORD:

			keystart = --scan; /* starts back there */
			/* find white space to get keyword length */
			for (; scan < eof; scan++)
			{
				/* +1 gets count, not array index */
				kwlen = 1 + scan - keystart;
				if (kwlen >= KWLEN) {
					printf("keyword too long\n");
					return -1;
				}

				/* check for whatespace character */
				c = *scan;
				if (c == ' '  || c == '\t' || c == '\n' ) {
					if (kwlen < 2) /* need at least 1 char + space */
						return -1;

					/* skip whitespace to get start of parameters */
					if (c != '\n') {
						for (;scan < eof; ++scan)
						{
							c = *scan;
							if (c == ' ' || c == '\t')
								continue;
							/* rewind, continues main loop */
							--scan;
							goto SCAN_PARAMS_READY;
						}
					}
					else { /* c == '\n'  */
						goto SINGLE_KEYWORD;
					}
					break;
				}
			}
			if (scan >= eof)
				return -1;

SCAN_PARAMS_READY:	/* got keyword with parameters, check keyword and
			 * change to parameter scan state if valid.
			 */
			memset(kwcmp, 0, sizeof(kwcmp));
			strncpy(kwcmp, keystart, --kwlen); /* kwlen includes space */

			key = find_keyword(kwcmp, kwlen);
			if (key == -1) {
				printf("invalid keyword: [%s]\n", kwcmp);
				return -1;
			}
			else {
				state = STATE_SCAN;
			}
			continue;


SINGLE_KEYWORD:		/* no parameters */
			memset(kwcmp, 0, sizeof(kwcmp));
			strncpy(kwcmp, keystart, --kwlen);

			key = find_keyword(kwcmp, kwlen);
			if (key == -1) {
				printf("could not find keyword: [%s]\n", kwcmp);
				return -1;
			}
			/* single keyword, no parameters */
			if (pod_enact_option(key, NULL, 0))
				return -1;
			key = -1;
			state = STATE_NEWLINE;

		break;


		/* read keyword parameters */
		case STATE_SCAN:
			scanstart = scan;
			--scan;
			/* scans until newline */
			if (key < 0)
				return -1;
			for(; scan < eof; ++scan)
			{
				if (*scan == '\n') {
					size_t param_size = 1 + scan - scanstart;
					char params[MAX_PARAM];

					if (param_size >= MAX_PARAM) {
						printf("params too big\n");
						return -1;
					}

					/* use buffer for params */
					snprintf(params, param_size, scanstart);
					params[param_size] = '\0';

					r = pod_enact_option(key, params, param_size);
					if (r) { /* chroot on 2'nd pass */
						return -1;
					}

					state = STATE_NEWLINE;
					break;
				}
			}
			if (scan >= eof) {
				printf("missing newline at end of file\n");
				return -1;
			}

			/* set invalid key */
			key = -1;
		break;

		default: /* unknown state */
			return -1;
		}
	}


	if (g_firstpass) {
		/* additional options to add?*/
		if (pass1_finalize()) {
			printf("pass1_finalize()\n");
			return -1;
		}

		/* add rdonly dirs, sort all path nodes */
		if (prepare_mountpoints()) {
			printf("prepare_mountpoints()\n");
			return -1;
		}
		/* make sure chroot path is intact */
		return do_chroot_setup();
	}
	else {  /* second pass finished, do binds and chroot */
		struct path_node *n;
		unsigned long remountflags =	  MS_REMOUNT
						| MS_NOSUID
						| MS_NOEXEC
						| MS_NODEV
						| MS_RDONLY
						| MS_UNBINDABLE;

		if (capbset_drop(g_fcaps)) {
			printf("failed to set bounding caps\n");
			return -1;
		}
		/* actually do bind/remount */
		n = g_mountpoints;
		while (n)
		{
			if (prep_bind(n)) {
				printf("prep_bind()\n");
				return -1;
			}
			n = n->next;
		}
		n = g_mountpoints;
		while(n)
		{
			if (do_bind(n)) {
				printf("do_bind()\n");
				return -1;
			}
			n = n->next;
		}
		if (mount(g_chroot_path, g_chroot_path, "bind",
					MS_BIND, NULL)) {
			printf("could not bind mount: %s\n", strerror(errno));
			return -1;
		}
		if (mount(NULL, g_chroot_path, "bind",
					MS_BIND|remountflags, NULL)) {
			printf("could not bind mount: %s\n", strerror(errno));
			return -1;
		}
		if (mount(NULL, g_chroot_path, NULL, MS_PRIVATE/*|MS_REC*/, NULL)) {
			printf("could not make slave: %s\n", strerror(errno));
			return -1;
		}

		/* this one may be redundant?
		 * TODO test again, lost the chroot escape code :\ */
		if (chdir(g_chroot_path) < 0) {
			printf("chdir(\"/\") failed: %s\n", strerror(errno));
			return -1;
		}
		if (mount(g_chroot_path, "/", NULL, MS_MOVE, NULL) < 0) {
			printf("mount / MS_MOVE failed: %s\n", strerror(errno));
			return -1;
		}
		printf("chroot(%s)\n", g_chroot_path);
		r = chroot(g_chroot_path);
		if (r < 0) {
			printf("chroot failed: %s\n", strerror(errno));
			return -1;
		}
		/*chroot doesnt change CWD, so we must.*/
		if (chdir("/") < 0) {
			printf("chdir(\"/\") failed: %s\n", strerror(errno));
			return -1;
		}

		mkdir("/tmp", 0750);
		chown("/tmp", g_ruid, g_rgid);

	}
	return 0;
}








