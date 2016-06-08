/* (c) 2015 Michael R. Tirado -- GPLv3, GNU General Public License, version 3.
 * contact: mtirado418@gmail.com
 *
 * pod.c
 *
 * loads configuration file, and enacts options defined therein
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
#include <time.h>
#include "pod.h"
#include "misc.h"
#include "util/seccomp_helper.h"
#include "eslib/eslib.h"
#include "eslib/eslib_rtnetlink.h"


#ifdef X11OPT
	#include <X11/Xauth.h>
	extern char *x11get_displaynum(char *display, unsigned int *outlen);
	extern char g_x11meta_sockname[MAX_SYSTEMPATH];
	extern unsigned int g_x11meta_width;
	extern unsigned int g_x11meta_height;
#endif

/*
 *  prevent these exact paths from being mounted without MS_RDONLY.
 *  you can mount writable directories after these locations.
 *  theres probably more paths i should add to this list.
 *  be extra careful if running root pods.
 */
static char *g_rdonly_dirs[] =
{
	"/test",
	"/etc",
	"/sbin",
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
	"/.Xauthority",
	"/root",
	POD_PATH,
	JETTISON_USERCFG,
	JETTISON_BLACKLIST,
	IPVLAN_COUNT_LOCKFILE
};
#define BLACKLIST_COUNT (sizeof(g_blacklist_paths) / sizeof(*g_blacklist_paths))

struct path_node *g_mountpoints;

/* external variables from jettison.c
 * non-jettison.c C callers will have to define these.
 */
extern char g_pty_slavepath[MAX_SYSTEMPATH];
extern gid_t g_rgid;
extern uid_t g_ruid;
extern int g_tracecalls;
extern pid_t g_mainpid;
extern int g_daemon;
extern int g_blacklist;
#define MAX_PARAM (MAX_SYSTEMPATH * 4)
char g_params[MAX_PARAM];

/* much globals */
unsigned int g_lineno;
size_t g_filesize;
char *g_filedata;
int g_allow_dev;
int g_firstpass;
unsigned int g_podflags;

int g_fcaps[NUM_OF_CAPS];
int g_syscalls[MAX_SYSCALLS];
int g_blkcalls[MAX_SYSCALLS];
unsigned int  g_syscall_idx;
unsigned int  g_blkcall_idx;
char g_chroot_path[MAX_SYSTEMPATH];
char g_errbuf[ESLIB_LOG_MAXMSG];

extern struct newnet_param g_newnet;
extern struct user_privs g_privs;

static int pod_load_config(char *data, size_t size);
static int pod_enact_option(unsigned int option, char *params, size_t size);

/* home root is a special case since eslib considers / to be an invalid path */
struct path_node *g_homeroot;

/*
 * This keyword array is in sync with the option enum in pod.h
 */
#define KWLEN  32 /* maximum string length */
static char keywords[KWCOUNT][KWLEN] =
{
	{ "newnet"	},  /* create new network namespace */
	{ "newpts"	},  /* creates a new /dev/pts instance */
	{ "noproc"	},  /* do not mount /proc */
	/*{ "slog"	},*//* pod wants to write to system log */
	{ "home_exec"	},  /* mount empty home dir with exec flag */
#ifdef X11OPT
	{ "x11"         },  /* bind mount X11 socket and generate auth file */
	{ "xephyr"	},  /* isolate X11 session using Xephyr */
#endif

	{ "- - - - - - -" }, /* cutoff for podflags */

	{ "seccomp_allow" }, /* add a syscall to seccomp whitelist.
			       otherwise, everything is allowed. */
	{ "seccomp_block" }, /* block syscall without sigkill (if using --strict) */
	{ "file"          }, /* bind mount file with options w,r,x,d,s */
	{ "home"	  }, /* ^  -- but $HOME/file is rooted in /podhome  */
	{ "capability"	  }, /* leave capability in bounding set */
	{ "machine-id"	  }, /* specify or generate a /etc/machine-id string */
};

static void free_pathnodes()
{
	struct path_node *tmp;
	while (g_mountpoints)
	{
		tmp = g_mountpoints->next;
		free(g_mountpoints);
		g_mountpoints = tmp;
	}
}

/* if anything fails between pod_prepare or on pod_enter */
int pod_free()
{
	memset(g_chroot_path, 0, sizeof(g_chroot_path));
	if (g_filedata) {
		free(g_filedata);
		g_filedata = NULL;
	}
	free_pathnodes();
	return 0;
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
			if (path[len] <= 32) /* space */
				return 1;
		}

	}
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
	char *path = NULL;
	int r;
	ino_t root_ino;
	ino_t file_ino;
	unsigned int len;
	uid_t fuid;

	if (env == NULL) {
		printf("no environ??\n");
		return NULL;
	}
	while(*env)
	{
		if (strncmp(*env, "HOME=", 5) == 0) {
			path = &(*env)[5];
			len = strnlen(path, MAX_SYSTEMPATH);
			if (len >= MAX_SYSTEMPATH || len == 0)
				goto bad_path;
			if (chop_trailing(path, MAX_SYSTEMPATH, '/'))
				goto bad_path;
			if (eslib_file_path_check(path))
				goto bad_path;
			r = eslib_file_exists(path);
			if (r == -1 || r == 0)
				goto bad_path;

			root_ino = eslib_file_getino("/");
			file_ino = eslib_file_getino(path);
			if (root_ino == 0 || file_ino == 0) {
				printf("inode error\n");
				return NULL;
			}
			if (root_ino == file_ino) {
				printf("home(%s) cannot be a root inode\n", path);
				return NULL;
			}
			/* validate homepath */
			if (check_blacklisted(path)) {
				printf("$HOME is blacklisted: %s\n", path);
				return NULL;
			}
			if (eslib_file_isdir(path) != 1) {
				printf("$HOME is not a directory: %s\n", path);
				return NULL;
			}
			fuid = eslib_file_getuid(path);
			if (fuid == (uid_t)-1)
				return NULL;
			if (fuid != g_ruid) {
				printf("$HOME permission denied: %s\n", path);
				return NULL;
			}
			return path;
		}
		++env;
	}
	printf("could not find $HOME environment variable\n");
	return NULL;

bad_path:
	printf("bad $HOME environment variable: %s\n", path);
	return NULL;
}

/* looks in ~/.pods then /etc/jettison/pods as fallback path */
static FILE *get_configfile(char *filepath)
{
	char fallback[MAX_SYSTEMPATH];
	FILE *file = NULL;
	char *filename = NULL;
	char *home = NULL;

	filename = eslib_file_getname(filepath);
	if (filename == NULL) {
		printf("bad filename\n");
		return NULL;
	}

	/* try absolute path */
	file = fopen(filepath, "r");
	if (file == NULL && errno == ENOENT) {
		memset(fallback, 0, sizeof(fallback));
		home = gethome();
		if (home == NULL) {
			return NULL;
		}
		/* try home pod directory */
		snprintf(fallback, sizeof(fallback), "%s/.pods/%s", home, filename);
		file = fopen(fallback, "r");
		if (file == NULL && errno == ENOENT) {
			/* try stock pod directory */
			snprintf(fallback, sizeof(fallback),
					"%s/%s", JETTISON_STOCKPODS, filename);
			file = fopen(fallback, "r");
			if (file == NULL) {
				goto err_ret;
			}
			else {
				return file;
			}
		}
		else if (file != NULL) {
			return file;
		}
	}
	else if (file != NULL) {
		return file;
	}
err_ret:
	printf("could not locate pod file %s.\nprovide the full path to file",filename);
	printf("or create a new one at ~/.pods or %s\n", JETTISON_STOCKPODS);
	return NULL;
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
	struct stat st;

	if (outpath == NULL || outflags == NULL)
		return -1;

	if (MAX_SYSTEMPATH < 256) {
		printf("MAX_SYSTEMPATH is too small (<256)\n");
		return -1;
	}

#ifdef X11OPT
	g_x11meta_width = 0;
	g_x11meta_height = 0;
#endif

	g_podflags = 0;
	g_allow_dev = 0;
	g_firstpass = 1;
	g_syscall_idx = 0;
	g_blkcall_idx = 0;
	g_homeroot = NULL;
	g_filedata = NULL;
	g_mountpoints = NULL;
	memset(g_fcaps, 0, sizeof(g_fcaps));
	memset(g_chroot_path, 0, sizeof(g_chroot_path));

	for (i = 0; i < MAX_SYSCALLS / sizeof(unsigned int); ++i)
	{
		g_syscalls[i] = -1;
		g_blkcalls[i] = -1;
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

	file = get_configfile(filepath);
	if (file == NULL) {
		printf("could not read pod configuration file: %s\n", filepath);
		return -1;
	}
	/* check chroot path */
	snprintf(g_chroot_path, MAX_SYSTEMPATH, "%s/%s/%s", POD_PATH, pwuser, filename);
	if (strnlen(g_chroot_path, MAX_SYSTEMPATH) >= MAX_SYSTEMPATH-100) {
		printf("chroot path too long: %s\n", g_chroot_path);
		goto err_close;
	}
	if (eslib_file_path_check(g_chroot_path)) {
		printf("bad chroot path\n");
		goto err_close;
	}
	r = stat(g_chroot_path, &st);
	if (r == 0) {
		if (!S_ISDIR(st.st_mode)) {
			printf("chroot path(%s) is not a directory\n", g_chroot_path);
			goto err_close;
		}
		if (st.st_uid != 0 || st.st_gid != 0) {
			printf("chroot path(%s) must be owned by root\n", g_chroot_path);
			goto err_close;
		}
	}
	else if (r == -1 && errno == ENOENT) {
		if (mkdir(g_chroot_path, 0770)) {
			printf("chroot path(%s) couldn't be created\n", g_chroot_path);
			goto err_close;
		}
		if (chmod(g_chroot_path, 0770)) {
			printf("chmod(%s): %s\n", g_chroot_path, strerror(errno));
			goto err_close;
		}
	}
	else {
		printf("stat: %s\n", strerror(errno));
		goto err_close;
	}

	printf("filename: %s\r\n", filename);
	printf("chroot path: %s\r\n", g_chroot_path);

	fseek(file, 0, SEEK_END);
	g_filesize = ftell(file);
	fseek(file, 0, SEEK_SET);

	g_filedata = (char *)malloc(g_filesize+1); /* + terminator */
	if (g_filedata == NULL) {
		printf("malloc error\n");
		goto err_close;
	}
	if (fread(g_filedata, 1, g_filesize, file) != g_filesize){
		goto err_free_close;
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
	*outflags = g_podflags;
	strncpy(outpath, g_chroot_path, MAX_SYSTEMPATH-1);
	outpath[MAX_SYSTEMPATH-1] = '\0';
	return 0;

err_free_close:
	pod_free();
err_close:
	fclose(file);
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
		if (eslib_file_mkdirpath(g_chroot_path, 0775, 0)) {
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
	mkdir(podhome, 0770);
	if (chown(g_chroot_path, 0, 0)) {
		printf("chown %s failed\n", podhome);
		return -1;
	}
	setuid(0);
	setgid(0);
	if (chmod(g_chroot_path, 0775)) {
		printf("chmod %s: %s\n", g_chroot_path, strerror(errno));
		return -1;
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
	if (node->nodetype == NODE_HOME) {
		setuid(g_ruid);
	}

	src = node->src;
	dest = node->dest;

	if (eslib_file_path_check(src) || eslib_file_path_check(dest)) {
		return -1;
	}
	if (strncmp(dest, g_chroot_path, strnlen(g_chroot_path, MAX_SYSTEMPATH-1))) {
		return -1; /* dest is not in pod root... */
	}

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
				snprintf(g_errbuf, sizeof(g_errbuf),
					"prep_bind dest is not a directory: %s", dest);
				eslib_logerror("jettison", g_errbuf);
				return -1;
			}
			else if (r == -1) {
				return -1;
			}
		}
	}
	else { /* did not exist */
		if (isdir == 1) {
			if (eslib_file_mkdirpath(dest, 0775, 0)  == -1) {
				snprintf(g_errbuf, sizeof(g_errbuf),
					"prep_bind mkdir failed: %s", dest);
				eslib_logerror("jettison", g_errbuf);
				return -1;
			}
		}
		else {
			if (eslib_file_mkfile(dest, 0775, 0) == -1) {
				snprintf(g_errbuf, sizeof(g_errbuf),
					"prep_bind mkfile failed: %s", dest);
				eslib_logerror("jettison", g_errbuf);
				return -1;
			}
			if (chmod(dest, 0770)) {
				printf("chmod: %s\n", strerror(errno));
				return -1;
			}
		}
	}

	if (node->nodetype == NODE_HOME) {
		if (setuid(0)) {
			printf("setuid: %s\n", strerror(errno));
			return -1;
		}
	}
	return 0;
}

/* user is mounting entire $HOME to /podhome */
static int create_homeroot(unsigned long mntflags, unsigned long nodetype)
{
	struct path_node *node;
	char *homepath;

	if (g_homeroot) {
		printf("duplicate home root\n");
		return -1;
	}
	homepath = gethome();
	if (homepath == NULL)
		return -1;
	node = malloc(sizeof(*node));
	if (node == NULL)
		return -1;

	memset(node, 0, sizeof(*node));
	snprintf(node->src, MAX_SYSTEMPATH, "%s", homepath);
	snprintf(node->dest, MAX_SYSTEMPATH, "%s/podhome", g_chroot_path);
	node->srclen = strnlen(node->src, MAX_SYSTEMPATH-1);
	node->destlen = strnlen(node->dest, MAX_SYSTEMPATH-1);
	node->mntflags = mntflags;
	node->nodetype = nodetype;
	g_homeroot = node;
	return 0;
}

int create_pathnode(char *params, size_t size, int home)
{
	char src[MAX_SYSTEMPATH];
	char dest[MAX_SYSTEMPATH];
	char *path;
	char *homepath;
	struct path_node *node;
	unsigned int i, len;
	unsigned long remountflags;
	unsigned long nodetype = 0;
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
	if (home)
		nodetype = NODE_HOME;

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
#ifdef PODROOT_HOME_OVERRIDE
			if (home && c == 'R') {
				nodetype = NODE_PODROOT_HOME_OVERRIDE;
				break;
			}
#endif
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


	/* check for case where user mounts entire home into pod */
	if (path[0] == '/' && path[1] == '\0') {
		if (!home) {
			printf("cannot mount filesystem root directory\n");
			return -1;
		}
		else {
			return create_homeroot(remountflags, 0);
		}
	}
	/* eslib doesn't want trailing slashes */
	if (chop_trailing(path, MAX_SYSTEMPATH, '/'))
		return -1;

	if (eslib_file_path_check(path)) {
		printf("bad path\n");
		return -1;
	}
	if (check_blacklisted(path)) {
		printf("path blacklisted: %s\n", path);
		return -1;
	}

	/* setup mount as / == /$HOME/user/ to be mounted at /podhome
	 * e.g. /.bashrc translates to POD_PATH/$USER/filename.pod/podhome/.bashrc
	 */
	if (home) {
		homepath = gethome();
		if (homepath == NULL)
			return -1;

		if (nodetype != NODE_PODROOT_HOME_OVERRIDE) {
			snprintf(src,  MAX_SYSTEMPATH-1, "%s%s", homepath, path);
			snprintf(dest, MAX_SYSTEMPATH-1, "%s/podhome%s",
					g_chroot_path, path);
		}
		else {
#ifdef PODROOT_HOME_OVERRIDE
			snprintf(src,  MAX_SYSTEMPATH-1, "%s%s", homepath, path);
			snprintf(dest, MAX_SYSTEMPATH-1, "%s%s", g_chroot_path, path);
#else
			return -1;
#endif
		}
	}
	else { /* setup mount normally */
		strncpy(src , path, MAX_SYSTEMPATH-1);
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

	node->nodetype = nodetype;
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
 * 1 if any path_nodes *start with* path
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

/* return *exact* matching node,
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

static int do_podroot_home_override()
{
#ifdef PODROOT_HOME_OVERRIDE
	struct path_node *n, *prev, *tmp;
	struct path_node *ovr_list = NULL;
	if (g_mountpoints == NULL)
		return -1;

	/* enumerate override nodes */
	n = g_mountpoints;
	while (n)
	{
		if (n->nodetype == NODE_PODROOT_HOME_OVERRIDE) {
			tmp = malloc(sizeof(struct path_node));
			if (tmp == NULL) {
				return -1;
			}
			memcpy(tmp, n, sizeof(struct path_node));
			tmp->next = ovr_list;
			ovr_list = tmp;
		}
		n = n->next;
	}

	/* remove nodes that are being replaced */
	while (ovr_list)
	{
		n = g_mountpoints;
		prev = NULL;
		while (n)
		{
			if (strncmp(ovr_list->dest, n->dest, n->destlen+1) == 0
					&& n->nodetype != NODE_PODROOT_HOME_OVERRIDE) {
				if (prev == NULL) {
					g_mountpoints = n->next;
				}
				else {
					prev->next = n->next;
				}
				tmp = n->next;
				free(n);
				n = tmp;
			}
			else {
				prev = n;
				n = n->next;
			}
		}
		tmp = ovr_list;
		ovr_list = tmp->next;
		free(tmp);
	}

#endif
	return 0;
}

/* sort mountpoints by length
 *
 * sort paths shortest to longest and check for duplicate entries.
 * sorting enables predictable hierarchical bind order
 * e.g. /usr always gets mounted before /usr/lib
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
		g_mountpoints->nodetype = NODE_EMPTY;
		printf("rdonly node marked as empty: %s\n", opt);
	}

	if (do_podroot_home_override())
		return -1;

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

#ifdef X11OPT
static int do_x11_socketbind(char *socket_src, char *socket_dest)
{
	struct path_node xsock;
	char destdir[MAX_SYSTEMPATH];

	memset(&xsock, 0, sizeof(xsock));
	memset(destdir, 0, sizeof(destdir));

	if (!socket_src || !socket_dest)
		return -1;

	/* bind mount X11 socket into pod */
	strncpy(xsock.src,  socket_src, sizeof(xsock.src));
	strncpy(xsock.dest, socket_dest, sizeof(xsock.dest));
	xsock.src[sizeof(xsock.src)-1] = '\0';
	xsock.dest[sizeof(xsock.dest)-1] = '\0';

	xsock.mntflags = MS_UNBINDABLE;
	if (prep_bind(&xsock)) {
		printf("prep_bind(%s, %s) failed\n", xsock.src, xsock.dest);
		return -1;
	}
	if (chown(xsock.dest, g_ruid, 0)) {
		printf("error setting x11 socket group\n");
		return -1;
	}
	snprintf(destdir, MAX_SYSTEMPATH, "%s/tmp/.X11-unix", g_chroot_path);
	if (chown(destdir, 0, 0)) {
		printf("chown: %s\n", strerror(errno));
		return -1;
	}
	if (chmod(destdir, 01777)) {
		printf("chmod: %s\n", strerror(errno));
		return -1;
	}
	if (pathnode_bind(&xsock)) {
		printf("pathnode_bind(%s, %s) failed\n", xsock.src, xsock.dest);
		return -1;
	}

	return 0;
}

static int x11meta_hookup(char *sock_src, char *sock_dest, char *displaynum)
{
	char lockpath[MAX_SYSTEMPATH];
	snprintf(sock_src, MAX_SYSTEMPATH, "%s/.x11meta/tmp/.X11-unix/X%s",
			POD_PATH, displaynum);
	snprintf(sock_dest,MAX_SYSTEMPATH, "%s/tmp/.X11-unix/X0", g_chroot_path);
	if (eslib_proc_setenv("DISPLAY", ":0.0")) {
		return -1;
	}
	if(do_x11_socketbind(sock_src, sock_dest)) {
		return -1;
	}
	if (unlink(sock_src)) {
		printf("unlink(%s): %s\n", sock_src, strerror(errno));
		return -1;
	}
	snprintf(lockpath, sizeof(lockpath), "%s/.x11meta/tmp/.X%s-lock",
			POD_PATH, displaynum);
	if (unlink(lockpath)) {
		printf("unlink(%s): %s\n", lockpath, strerror(errno));
		return -1;
	}
	return 0;
}

static int X11_hookup()
{
	char newpath[MAX_SYSTEMPATH];
	char sock_src[MAX_SYSTEMPATH];
	char sock_dest[MAX_SYSTEMPATH];
	char *displaynum;
	Xauth *xau = NULL;
	FILE *fin, *fout;
	char *xauth_file = eslib_proc_getenv("XAUTHORITY");
	char *display = eslib_proc_getenv("DISPLAY");
	unsigned int dlen;
	int found = 0;

	memset(newpath, 0, MAX_SYSTEMPATH);
	memset(sock_src, 0, MAX_SYSTEMPATH);
	memset(sock_dest, 0, MAX_SYSTEMPATH);

	displaynum = x11get_displaynum(display, &dlen);
	if (displaynum == NULL)
		goto disp_err;

	if (g_x11meta_sockname[0] != '\0') {
		return x11meta_hookup(sock_src, sock_dest, displaynum);
	}

	setuid(g_ruid);
	if (xauth_file == NULL) {
		printf("missing XAUTHORITY env var\n");
		return -1;
	}
	if (eslib_file_path_check(xauth_file)) {
		printf("XAUTHORITY bad path\n");
		return -1;
	}

	snprintf(sock_src, MAX_SYSTEMPATH, "/tmp/.X11-unix/X%s", displaynum);
	snprintf(sock_dest,MAX_SYSTEMPATH, "%s/tmp/.X11-unix/X%s",
			g_chroot_path, displaynum);


	/* don't bother trying to copy auth file if mounting entire dir */
	if (g_homeroot->nodetype != NODE_EMPTY) {
		printf("------------------------------------------------------------\n");
		printf("WARNING: you are mounting entire home directory with X11\n");
		printf("option selected. this will leak X11 auth data for every\n");
		printf("screen this user controls. if you only use a single X11\n");
		printf("screen, this is no problem.\n");
		printf("\n");
		printf("if user has many screens, this could be bad depending on\n");
		printf("where the X11 sockets are listening. you should make sure\n");
		printf("socket is only available through /tmp. it is best practice\n");
		printf("to avoid mounting entire home directory.\n");
		printf("------------------------------------------------------------\n");
		setuid(0);
		return do_x11_socketbind(sock_src, sock_dest);
	}

	snprintf(newpath, sizeof(newpath),
			"%s/podhome/.Xauthority", g_chroot_path);
	fin = fopen(xauth_file, "r");
	if (fin == NULL) {
		printf("fopen(%s): %s\n", xauth_file, strerror(errno));
		return -1;
	}
	fout = fopen(newpath, "w+");
	if (fout == NULL) {
		printf("fopen(%s): %s\n", newpath, strerror(errno));
		goto fail_close;
	}

	/* copy auth info for current display */
	while(1)
	{
		xau = XauReadAuth(fin);
		if (xau == NULL) {
			if (!found) {
				printf("xauth entry for display not found\n");
				goto fail_close;
			}
			else {
				break;
			}
		}
		else if (xau->number_length == dlen
				&& strncmp(xau->number, displaynum, dlen) == 0) {
			if (XauWriteAuth(fout, xau) != 1) {
				printf("XauWriteAuth failed\n");
				goto fail_close;
			}
			found = 1;
		}
		XauDisposeAuth(xau);

	}
	fclose(fin);
	fclose(fout);

	setuid(0);
	return do_x11_socketbind(sock_src, sock_dest);

disp_err:
	printf("DISPLAY env error\n");
	return -1;

fail_close:
	fclose(fin);
	fclose(fout);
	return -1;
}
#endif

static int parse_newnet(char *params, size_t size)
{
	char type[32];
	unsigned int typelen;
	unsigned int devlen;
	unsigned int addrlen;
	size_t i, z;

	if (size <= 1)
		return -1;
	if (g_newnet.active) {
		printf("only one newnet is supported\n");
		return -1;
	}
	memset(type, 0, sizeof(type));
	for (i = 0; i < size; ++i) /* space separated */
		if (params[i] == ' ')
			break;
	typelen = i;
	if (typelen+1 >= sizeof(type)) {
		printf("newnet type too long\n");
		return -1;
	}
	strncpy(type, params, typelen);

	/* get kind */
	if (strncmp(type, "none", 5) == 0)
		g_newnet.kind = ESRTNL_KIND_UNKNOWN;
	else if (strncmp(type, "loop", 5) == 0)
		g_newnet.kind = ESRTNL_KIND_LOOP;
#ifdef NEWNET_VETHBR
	else if (strncmp(type, "vethbr", 7) == 0)
		g_newnet.kind = ESRTNL_KIND_VETHBR;
#endif
#ifdef NEWNET_IPVLAN
	else if (strncmp(type, "ipvlan", 7) == 0)
		g_newnet.kind = ESRTNL_KIND_IPVLAN;
#endif
#ifdef NEWNET_MACVLAN
	else if (strncmp(type, "macvlan", 8) == 0)
		g_newnet.kind = ESRTNL_KIND_MACVLAN;
#endif

	switch (g_newnet.kind)
	{
	case ESRTNL_KIND_IPVLAN:
	case ESRTNL_KIND_MACVLAN:
		/* read device string */
		z = ++i;
		for (; i < size; ++i)
			if (params[i] == ' ')
				break;
		if (i >= size) {
			printf("bad parameter(no device?)\n");
			return -1;
		}
		devlen = i - z;
		if (devlen == 0 || devlen >= sizeof(g_newnet.dev)) {
			printf("bad master devlen: %d\n", devlen);
			return -1;
		}
		strncpy(g_newnet.dev, &params[z], devlen);

		/* read hwaddr string */
		if (g_newnet.kind == ESRTNL_KIND_MACVLAN) {
			int cnt = 0;
			z = ++i;
			for (; i < size; ++i) {
				if (params[i] == ':')
					++cnt;
				else if (params[i] == ' ')
					break;
			}
			if (cnt == 0) {
				printf("macvlan needs mac address, ");
				printf("use **:**:**:**:**:** for a random one. \n");
				return -1;
			}
			if (i >= size)
				return -1;
			addrlen = i - z;
			if (addrlen == 0 || addrlen >= sizeof(g_newnet.hwaddr)) {
				printf("bad hwaddr: %d\n", addrlen);
				return -1;
			}
			strncpy(g_newnet.hwaddr, &params[z], addrlen);
		}

		/* read ipaddr string */
		z = ++i;
		for (; i < size; ++i)
			if (params[i] == ' ' || params[i] == '\0')
				break;
		addrlen = i - z;
		if (addrlen == 0 || addrlen >= sizeof(g_newnet.addr)) {
			printf("bad addr: %d\n", addrlen);
			return -1;
		}
		strncpy(g_newnet.addr, &params[z], addrlen);

		/* does addr have subnet mask? */
		for (i = 0; i < addrlen; ++i) {
			if (g_newnet.addr[i] == '/') {
				char *err = NULL;
				long netmask;
				g_newnet.addr[i] = '\0';
				if (++i >= addrlen) { /* slash was last char */
					printf("bad subnet mask\n");
					return -1;
				}
				errno = 0;
				netmask = strtol(&g_newnet.addr[i], &err, 10);
				if (err == NULL || *err || errno) {
					printf("bad subnet mask value\n");
					return -1;
				}
				if (netmask < 0 || netmask > 32) {
					printf("invalid netmask\n");
					return -1;
				}
				g_newnet.netmask = netmask;
				strncpy(g_newnet.prefix, &g_newnet.addr[i], 2);
				g_newnet.prefix[2] = '\0';
				break;
			}
		}
		if (i >= addrlen) {
			snprintf(g_newnet.prefix, 3, "%d", DEFAULT_NETMASK_PREFIX);
			g_newnet.netmask = DEFAULT_NETMASK_PREFIX;
		}
		break;
	case ESRTNL_KIND_VETHBR:
		printf("todo...\n");
		return -1;
	case ESRTNL_KIND_LOOP:
	case ESRTNL_KIND_UNKNOWN:
		break;
	default:
		printf("erroneous type: %s\n", type);
		return -1;
	}

	g_newnet.active = 1;
	return 0;
}

static int load_seccomp_blacklist(const char *file)
{
	char rdline[MAX_SYSCALL_DEFLEN*2];
	FILE *f;
	int syscall_nr;
	unsigned int i;

	g_blkcall_idx = 0;
	g_syscall_idx = 0;
	for (i = 0; i < MAX_SYSCALLS / sizeof(unsigned int); ++i)
	{
		g_blkcalls[i] = -1;
		g_syscalls[i] = -1;
	}

	f = fopen(file, "r");
	if (f == NULL) {
		printf("fopen(%s): %s\n", file, strerror(errno));
		return -1;
	}
	while (1)
	{
		if (fgets(rdline, sizeof(rdline), f) == NULL) {
			break;
		}
		chop_trailing(rdline, sizeof(rdline), '\n');
		if (rdline[0] == '\0')
			continue;
		syscall_nr = syscall_getnum(rdline);
		if (syscall_nr < 0) {
			printf("could not find syscall: %s\n", rdline);
			goto fail;
		}
		g_blkcalls[g_blkcall_idx] = syscall_nr;
		++g_blkcall_idx;
	}
	fclose(f);
	return 0;
fail:
	fclose(f);
	return -1;
}

#ifdef X11OPT
int read_x11meta_params(char *params, unsigned int size)
{
	char *err;
	char *wstr = NULL;
	char *hstr = NULL;
	unsigned long width, height;
	unsigned int i = 0;

	if (params == NULL || size == 0)
		return -1;

	/* get width/height strings */
	while (++i < size)
	{
		if (params[i] == ' ') {
			if (++i >= size) {
				return -1;
			}
			wstr = params;
			hstr = &params[i];
			params[i-1] = '\0';
			break;
		}
	}
	if (wstr == NULL || hstr == NULL) {
		printf("couldn't find x11 display width and/or height\n");
		return -1;
	}

	err = NULL;
	errno = 0;
	width = strtoul(wstr, &err, 10);
	if (err == NULL || *err || errno) {
		printf("bad width\n");
		return -1;
	}
	err = NULL;
	errno = 0;
	height = strtoul(hstr, &err, 10);
	if (err == NULL || *err || errno) {
		printf("bad height\n");
		return -1;
	}
	if (height <= 1 || height > 32000 || width <= 1 || width > 32000) {
		printf("bad width and/or height value\n");
		return -1;
	}
	g_x11meta_width  = width;
	g_x11meta_height = height;
	return 0;
}
#endif

/* some things need action on first pass. like setting flags, paths need to be
 * enumerated for sorting, newnet is handled completely in main thread */
static int pod_enact_option_pass1(unsigned int option, char *params, size_t size)
{
	if (option < OPTION_PODFLAG_CUTOFF) {
		/* set flag if below cutoff */
		g_podflags |= (1 << option);
	}
	switch (option)
	{
	/* file mount points need to be sorted after first pass */
	case OPTION_FILE:
		if (create_pathnode(params, size, 0)) {
			printf("file :%s\n", params);
			return -1;
		}
		break;

	case OPTION_HOME:
		if (create_pathnode(params, size, 1)) {
			printf("home :%s\n", params);
			return -1;
		}
		break;

	case OPTION_NEWNET:
		if (parse_newnet(params, size))
			return -1;
		break;

#ifdef X11OPT
	case OPTION_XEPHYR:
		if (params == NULL || size == 0) {
			printf("missing parameters, e.g: `xephyr 1024 768`\n");
			printf("params(%s)\n", params);
			return -1;
		}
		if (read_x11meta_params(params, size)) {
			printf("couldn't load x11meta display parameters\n");
			return -1;
		}
		break;
#endif
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
	int  r;
#ifdef USE_FILE_CAPS
	int  cap_nr;
	char cap_buf[MAX_CAP_DEFLEN];
#endif
	if (option >= KWCOUNT)
		return -1;

	/* first pass happens before we clone */
	if (g_firstpass == 1) {
		return pod_enact_option_pass1(option, params, size);
	}

	/* 2'nd pass, we've been cloned */
	memset(src,  0, sizeof(src));
	memset(dest, 0, sizeof(dest));
	memset(path, 0, sizeof(path));

	switch (option)
	{

	/* caller is responsible for hooking these up */
	case OPTION_NOPROC:
	/*case OPTION_SLOG:*/
	case OPTION_HOME_EXEC:
	case OPTION_NEWNET:
	case OPTION_NEWPTS:
		break;

	/* add a systemcall to the whitelist */
	case OPTION_SECCOMP_ALLOW:
		if (g_blacklist)
			break;

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
		if (g_blacklist)
			break;

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
	case OPTION_CAPABILITY:
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
#ifdef X11OPT
	case OPTION_X11:
	case OPTION_XEPHYR:
		break;
#endif

	case OPTION_MACHINEID:
		snprintf(path, sizeof(path), "%s/etc/machine-id", g_chroot_path);
		r = eslib_file_exists(path);
		if (r == -1) {
			printf("path error\n");
			return -1;
		}
		else if (r == 0) {
			if (eslib_file_mkfile(path, 0775, 0)) {
				printf("error creating: %s\n", path);
				return -1;
			}
		}
		if (chmod(path, 0775)) {
			printf("chmod: %s\n", strerror(errno));
			return -1;
		}
		if (params == NULL) {
			struct timespec t;
			clock_gettime(CLOCK_MONOTONIC_RAW, &t);
			/* assumes overflows are not saturated */
			if (create_machineid(path, NULL, 0x0f0f0f0f
							+(unsigned int)t.tv_nsec
							+(unsigned int)t.tv_sec
							+(unsigned int)g_mainpid)) {
				printf("create_machineid(NULL)\n");
				return -1;
			}
			return 0;
		}
		else if (create_machineid(path, params, 0)) {
			printf("create_machineid()\n");
			return -1;
		}
		break;
	default:
		printf("unknown option\n");
		return -1;
	}

	return 0;
}

static int find_keyword(char *kwcmp)
{
	int i = 0;
	for (; i < KWCOUNT; ++i)
	{
		if (strncmp(kwcmp, keywords[i], KWLEN) == 0)
			return i;
	}
	return -1;
}


/* final stage of pass 1, add things to config as needed */
static int pass1_finalize()
{
	char pathbuf[MAX_SYSTEMPATH];

#ifndef PODROOT_HOME_OVERRIDE
	/* whitelist jettison init program */
	snprintf(pathbuf, sizeof(pathbuf), "rx %s", INIT_PATH);
	if (create_pathnode(pathbuf, sizeof(pathbuf), 0)) {
		printf("couldn't create rdonly path(%s)\n", pathbuf);
		return -1;
	}

	/* whitelist jettison preload */
	snprintf(pathbuf, sizeof(pathbuf), "rx %s", PRELOAD_PATH);
	if (create_pathnode(pathbuf, sizeof(pathbuf), 0)) {
		printf("couldn't create rdonly path(%s)\n", pathbuf);
		return -1;
	}

	/* remount /podhome as empty node unless $HOME is already whitelisted */
	if (g_homeroot == NULL) {
		unsigned long mntflags = MS_NOEXEC|MS_NOSUID|MS_NODEV|MS_UNBINDABLE;
		if (g_podflags & (1 << OPTION_HOME_EXEC)) {
			mntflags &= ~MS_NOEXEC;
		}
		if (create_homeroot(mntflags, NODE_EMPTY)) {
			return -1;
		}
	}
	/* g_homeroot must always exist after pass1 */
	g_homeroot->next = g_mountpoints;
	g_mountpoints = g_homeroot;
#endif
	/* make tmp dir */
	snprintf(pathbuf, sizeof(pathbuf), "%s/tmp", g_chroot_path);
	mkdir(pathbuf, 0770);
	chmod(pathbuf, 01777);

	return 0;
}

static int pass2_finalize()
{
	char src[MAX_SYSTEMPATH];
	char dest[MAX_SYSTEMPATH];
	struct path_node tnode;

	/* remount /tmp as an "empty" node */
	memset(&tnode, 0, sizeof(tnode));
	snprintf(tnode.dest, MAX_SYSTEMPATH, "%s/tmp", g_chroot_path);
	tnode.mntflags = MS_UNBINDABLE|MS_NOEXEC|MS_NOSUID|MS_NODEV;
	tnode.nodetype = NODE_EMPTY;
	if (pathnode_bind(&tnode)) {
		printf("pathnode_bind(%s, %s) failed\n", tnode.src, tnode.dest);
		return -1;
	}

	/* hookup new pts instance */
	if (g_podflags & (1 << OPTION_NEWPTS)) {
		if (g_privs.newpts == 0) {
			printf("user is not authorized for newpts instance\n");
			printf("add newpts option to privilege file\n");
			return -1;
		}
#if 0
		/* we might need to work around a glibc issue. it assumes /dev/pts
		 * always exists, and trying to trick it is not easy. so for now
		 * programs that use glibc for pty operations may not work right.
		 * there is talk about a fix: https://github.com/lxc/lxd/issues/1724
		 * what i suspect may be happening: /dev/pts is hardcoded in glibc as
		 * the pty dir, but slave pty path points to real root /dev/pts, so
		 * mounting that particular terminal in (seen below) can not work.
		 * LD_PRELOAD hax maybe? :\
		 */
		if (!g_daemon) {
			memset(&tnode, 0, sizeof(tnode));
			snprintf(tnode.src, MAX_SYSTEMPATH, "%s", g_pty_slavepath);
			snprintf(tnode.dest, MAX_SYSTEMPATH, "%s%s",
					g_chroot_path, g_pty_slavepath);
			tnode.mntflags = MS_UNBINDABLE|MS_NOEXEC|MS_NOSUID;

			eslib_file_mkfile(tnode.dest, 0775, 0);
			if (pathnode_bind(&tnode)) {
				printf("pathnode_bind(%s,%s) failed\n", tnode.src, tnode.dest);
				return -1;
			}
			if (chown(tnode.dest, g_ruid, g_rgid)) {
				printf("pty link chown: %s\n", strerror(errno));
				return -1;
			}
		}
#endif
		snprintf(dest, MAX_SYSTEMPATH, "%s/dev/pts", g_chroot_path);
		if (mkdir(dest, 0755) && errno != EEXIST) {
			printf("mkdir(%s): %s\n", dest, strerror(errno));
			return -1;
		}
		if (chmod(dest, 0755)) {
			printf("chmod: %s\n", strerror(errno));
			return -1;
		}
		if (mount(0, dest, "devpts", 0, "newinstance") < 0)
			return -1;
		snprintf(src,  MAX_SYSTEMPATH, "%s/dev/pts/ptmx", g_chroot_path);
		if (chmod(src, 0666))
			return -1;
		snprintf(src,  MAX_SYSTEMPATH, "%s/dev/ptmx", g_chroot_path);
		if (symlink("pts/ptmx", src) && errno != EEXIST)
			return -1;
	}

#ifdef X11OPT
	/* hookup x11 */
	if (g_podflags & ((1 << OPTION_X11) | (1 << OPTION_XEPHYR))) {
		if (X11_hookup()) {
			printf("X11 hookup failed\n");
			return -1;
		}
	}
#endif

	/* protect podhome from non-root group */
	snprintf(dest,  MAX_SYSTEMPATH, "%s/podhome", g_chroot_path);
	if (chown(dest, g_ruid, 0)) {
		printf("podhome chown: %s\n", strerror(errno));
		return -1;
	}

	/* override pod config seccomp options with systemwide blacklist */
	if (g_blacklist) {
		if (load_seccomp_blacklist(JETTISON_BLACKLIST)) {
			return -1;
		}
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
			strncpy(kwcmp, keystart, kwlen-1); /* kwlen includes space */
			key = find_keyword(kwcmp);
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
			strncpy(kwcmp, keystart, kwlen-1);
			key = find_keyword(kwcmp);
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
		if (do_chroot_setup()) {
			printf("do_chroot_setup()\n");
			return -1;
		}
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
		return 0;
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
			if (pathnode_bind(n)) {
				printf("pathnode_bind()\n");
				return -1;
			}
			n = n->next;
		}

		if (pass2_finalize()) {
			printf("pass2_finalize()\n");
			return -1;
		}

		/* chroot */
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


	}
	return 0;
}


/*
 * set up the pods envionment and chroot.
 */
int pod_enter()
{
	int r;
	char pathbuf[MAX_SYSTEMPATH];
	unsigned long flags = MS_NOSUID
			    | MS_NOEXEC
			    | MS_NODEV
			    | MS_RDONLY;

	snprintf(pathbuf, sizeof(pathbuf), "%s/proc", g_chroot_path);
	if ((g_podflags & (1 << OPTION_NOPROC)) == 0) {
		mkdir(pathbuf, 0775);
		if (mount(0, pathbuf, "proc", flags, 0) < 0) {
			printf("couldn't mount proc(%s): %s\n",pathbuf,strerror(errno));
			goto err_free;
		}
	}
	else {
		r = eslib_file_exists(pathbuf);
		if (r == 1) {
			if (rmdir(pathbuf)) {
				printf("proc rmdir failed: %s\n", strerror(errno));
				return -1;
			}
		}
		else if (r == -1) {
			return -1;
		}
	}

	/* do the actual pod configuration now */
	r = pod_load_config(g_filedata, g_filesize);
	if (r < 0) {
		printf("pod_load_config(2) error: %d on line %d\n", r, g_lineno);
		goto err_free;
	}
	if (chmod("/tmp", 0777)) {
		printf("chmod(/tmp): %s\n", strerror(errno));
		return -1;
	}
	if (chown("/tmp", 0, 0)) {
		printf("chown(/tmp): %s\n", strerror(errno));
		return -1;
	}
	/* we're done here */
	pod_free();
	return 0;

err_free:
	pod_free();
	return -1;
}







