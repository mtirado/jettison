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
 * TODO stderr / stdout should be written to a separate log directory
 * in ~/pods/log  or something
 *
 * bugs: spaces / tabs after parameters may cause failure.
 *
 */

/*#define _DEFAULT_SOURCE*/
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

/* force these paths to be mounted as rdonly, we must prevent LD_PRELOAD
 * style attacks on executable with certain file capabilities set.
 * any paths at or below these are automatically remounted with MS_RDONLY.
 * if there are any special system mount points for whatever reason at these locations
 * you should specify them here since remount operation will not affect them.
 * for example, it would be fine to specify /usr instead of /usr/lib  and /usr/local/lib
 * but if on separate partitions, rdonly would not be applied to lower mountpoint.
 */
#define PATHCHECK_COUNT 3
static char *g_rdonly_paths[] =
{
	"/lib",
	"/usr/lib",
	"/usr/local/lib"
};

struct path_node
{
	struct path_node *next;
	char *path;
	unsigned long mntflags;
};
struct path_node *g_mountpoints;

/* external variables from jettison.c
 * XXX - non-jettison.c C callers will have to define these,
 * or we could provide pointer interface through pod_prepare
 */
extern char g_pty_slavepath[MAX_SYSTEMPATH];
extern gid_t g_rgid;
extern uid_t g_ruid;
extern int g_tracecalls;


/* right now the only heavy params are paths */
#define MAX_PARAM (MAX_SYSTEMPATH * 4)
char g_params[MAX_PARAM];

/* much globals */
unsigned int g_lineno;
size_t g_filesize;
char *g_filedata;
int g_allow_dev;
int g_firstpass;
unsigned int g_podflags;

/* if/when v4 comes out change the hardcoded 64's everywhere */
char g_fcaps[64];
/*char g_pcaps[64];*/
int g_syscalls[MAX_SYSCALLS];
unsigned int  g_syscall_idx;
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
	{ "newnetns"	},  /* create new network namespace TODO how to */
	{ "newpts"	},  /* creates a new /dev/pts instance */
	{ "noproc"	},  /* do not mount /proc */
	{ "slog"	},  /* pod wants to write to system log */
	/* podflags cutoff, don't actually use this... */
	{ "|||||||||||||" },
	{ "seccomp_allow" }, /* add a syscall to seccomp whitelist.
				if nothing is added, everything is allowed. */

	{ "file"        },  /* bind mount file with options w,r,x,d,s */
	{ "home"	},  /* ^  -- but $HOME/file is rooted in /podhome  */

	/* TODO make configuration file read string instead of number, like seccomp does */
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
	int slashidx;

	if (outpath == NULL || outflags == NULL)
		return -1;

	g_allow_dev = 0;
	g_podflags = 0;
	g_firstpass = 1;
	g_filedata = NULL;
	g_mountpoints = NULL;
	memset(g_chroot_path, 0, sizeof(g_chroot_path));
	memset(g_fcaps, 0, sizeof(g_fcaps));
	/*memset(g_pcaps, 0, sizeof(g_pcaps));*/
	g_syscall_idx = 0;

	for (i = 0; i < sizeof(g_syscalls) / sizeof(*g_syscalls); ++i)
	{
		g_syscalls[i] = -1;
	}

	file = fopen(filepath, "r");
	if (file == NULL) {
		printf("could not read pod configuration file: %s\n", filepath);
		return -1;
	}

	/* create chroot path, get filename */
	slashidx = 0;
	for (i = 0; i < MAX_SYSTEMPATH; ++i)
	{
		if (filepath[i] == '/')
			slashidx = i+1;
		else if (filepath[i] == '\0')
			break;
	}
	if (i >= MAX_SYSTEMPATH-1) {
		printf("pod file path too long\n");
		fclose(file);
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


	filename = &filepath[slashidx];
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
	printf("filename: %s\n", filename);
	printf("chroot path: %s\n", g_chroot_path);

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
		printf("pod_load_config error: %d on line %d\n", r, g_lineno);
		printf("podconfig: %s\n", filepath);
		pod_free();
		return -1;
	}
	g_firstpass = 0;

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



int do_chroot_setup()
{
	char podhome[MAX_SYSTEMPATH];
	int r;
	int l = strnlen(POD_PATH, MAX_SYSTEMPATH);

	if (l >= MAX_SYSTEMPATH / 2 || l <= 1)
		return -1;
	if (strncmp(g_chroot_path, POD_PATH, l) != 0)
		return -1;

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
	if (chown(podhome, g_ruid, g_rgid)) {
		printf("chown %s failed\n", podhome);
		return -1;
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
			if (root_ino == 0 || file_ino == 0)
				return NULL;
			if (root_ino == file_ino) {
				printf("home cannot be \"/\" (root inode)\n");
				return NULL;
			}
			if (chop_trailing(r, len+1, '/'))
				return NULL;
			printf("HOME=(%s)\n", r);
			return r;
		}
		++env;
	}
	printf("could not find $HOME environment variable\n");
	return NULL;
}

static int do_remount(char *dest, unsigned long flags)
{
	flags |= MS_REMOUNT;
	if (mount(NULL, dest, NULL, MS_BIND|flags, NULL)) {
		printf("remount failed: %s\n", strerror(errno));
		return -1;
	}
	if (mount(NULL, dest, NULL, MS_SLAVE|MS_REC, NULL)) {
		printf("could not make slave: %s\n", strerror(errno));
		return -1;
	}
	return 0;

}
static int do_bind(char *src, char *dest, unsigned long remountflags)
{
	int isdir, r;
	struct path_node *newpath;


	if (eslib_file_path_check(src) || eslib_file_path_check(dest))
		return -1;
	if (strncmp(dest, g_chroot_path, strnlen(g_chroot_path, MAX_SYSTEMPATH)))
		return -1; /* dest is not in pod root... */

	isdir = eslib_file_isdir(src);
	if (isdir == -1)
		return -1;

	printf("do_bind(%s, %s)\n", src, dest);

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
	/* do the bind */
	if (mount(src, dest, NULL, MS_BIND, NULL)) {
		printf("mount failed: %s\n", strerror(errno));
		return -1;
	}
	if (do_remount(dest, remountflags)) {
		printf("remount failed\n");
		return -1;
	}


	/* add to front of mountpoint list for later processing */
	newpath = malloc(sizeof(struct path_node));
	if (!newpath)
		return -1;
	r = strnlen(src, MAX_SYSTEMPATH);
	newpath->path = malloc(r+1);
	if (!newpath->path)
		return -1;
	strncpy(newpath->path, src, r);
	newpath->path[r] = '\0';
	newpath->mntflags = remountflags;
	newpath->next = g_mountpoints;
	g_mountpoints = newpath;
	return 0;
}


int do_option_bind(char *params, size_t size, int home)
{
	char src[MAX_SYSTEMPATH];
	char dest[MAX_SYSTEMPATH];
	char *path;
	char *homepath;
	uid_t fuid;
	unsigned int i;
	unsigned long remountflags;
	char c;

	if (size >= MAX_SYSTEMPATH) {
		printf("path too long\n");
		return -1;
	}

	if (params == NULL || size == 0)
		goto bad_param;

	 /*
	  * these appear to work, only if we remount.
	  * TODO test UNBINDABLE
	  */
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
			case 's': /* this is needed for file caps (i think) */
				remountflags &= ~MS_NOSUID;
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


	/* setup mount relative to /podhome ? */
	if (home) {
		homepath = gethome();
		if (homepath == NULL)
			return -1;
		if (eslib_file_isdir(homepath) != 1) {
			printf("not a directory: $HOME=%s\n", homepath);
			return -1;
		}
		fuid = eslib_file_getuid(homepath);
		if (fuid == (uid_t)-1)
			return -1;
		if (fuid != g_ruid) {
			printf("you don't own $HOME=%s\n", homepath);
			return -1;
		}
		snprintf(src,  MAX_SYSTEMPATH-1, "%s%s", homepath, path);
		snprintf(dest, MAX_SYSTEMPATH-1, "%s/podhome%s", g_chroot_path, path);
	}
	else { /* setup mount normally */
		strncpy(src , path, MAX_SYSTEMPATH-1);
		snprintf(dest, MAX_SYSTEMPATH-1, "%s%s", g_chroot_path, src);
	}
	src[MAX_SYSTEMPATH-1]  = '\0';
	dest[MAX_SYSTEMPATH-1] = '\0';

	return do_bind(src, dest, remountflags);

bad_param:
	printf("bad param");
	return -1;
}

/*
 * some paths must be forced as rdonly, to prevent user from injecting libs
 */
static int pod_process_mountpoints()
{
	char dest[MAX_SYSTEMPATH];
	unsigned int len[PATHCHECK_COUNT];
	unsigned int isbound[PATHCHECK_COUNT];
	unsigned int testbound[PATHCHECK_COUNT];
	unsigned int testlen;
	unsigned int i;
	unsigned long pathflags = MS_RDONLY
				| MS_NOSUID
				| MS_NODEV
				| MS_UNBINDABLE;


	for (i = 0; i < PATHCHECK_COUNT; ++i)
	{
		if (eslib_file_path_check(g_rdonly_paths[i]))
			return -1;
		isbound[i] = 0;
		testbound[i] = 0;
		len[i] = strlen(g_rdonly_paths[i]);
	}

	/* remount any points below paths */
	while (g_mountpoints)
	{
		for (i = 0; i < PATHCHECK_COUNT; ++i)
		{
			if (strncmp(g_mountpoints->path, g_rdonly_paths[i], len[i]))
				continue; /* no match */

			testlen = strnlen(g_mountpoints->path, MAX_SYSTEMPATH);
			testbound[i] = 1; /* only bind paths we matched here */
			if (testlen == len[i])
				isbound[i] = 1; /* exact path match, its already bound */
			snprintf(dest, MAX_SYSTEMPATH, "%s%s",
					g_chroot_path, g_mountpoints->path);
			printf("remount: %s\n", dest);
			if (do_remount(dest, g_mountpoints->mntflags|MS_RDONLY))
				return -1;
		}
		g_mountpoints = g_mountpoints->next;
	}

	/* remount the prescribed paths as read only */
	for (i = 0; i < PATHCHECK_COUNT; ++i)
	{
		if (testbound[i]) {
			snprintf(dest, MAX_SYSTEMPATH, "%s%s",
					g_chroot_path, g_rdonly_paths[i]);

			if (isbound[i]) {
				printf("remount, nobind: %s\n", dest);
				if (do_remount(dest, pathflags))
					return -1;
			}
			else {
				printf("bind, remount: %s\n", dest);
				/* do the bind */
				if (mount(dest, dest, NULL, MS_BIND, 0)) {
					printf("mount failed: %s\n", strerror(errno));
					return -1;
				}
				if (do_remount(dest, pathflags))
					return -1;
			}
		}
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
	char *err;
	unsigned int read_uint;
	char numbuf[32]; /* for strtol and whatnot */
	/*int is_pcap = 0;*/

	if (option >= KWCOUNT)
		return -1;

	/* first pass only cares about getting config flags */
	if (g_firstpass == 1) {
		if (option < OPTION_PODFLAG_CUTOFF) {
			/* set flag if below cutoff */
			g_podflags |= (1 << option);
		}
		return 0;
	}

	memset(src,  0, sizeof(src));
	memset(dest, 0, sizeof(dest));
	memset(path, 0, sizeof(path));

	switch (option)
	{

	case OPTION_SLOG:
		/* caller is responsible for hooking this up */
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

	/*
	 * add a systemcall to the seccomp whitelist filter.
	 */
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
			printf("seccomp_allow syscall name too long...\n");
			return -1;
		}
		memset(syscall_buf, 0, sizeof(syscall_buf));
		strncpy(syscall_buf, params, size);
		syscall_nr = syscall_getnum(syscall_buf);
		if (syscall_nr == -1) {
			printf("could not find syscall: %s\n", syscall_buf);
			return -1;
		}
		g_syscalls[g_syscall_idx] = syscall_nr;
		++g_syscall_idx;
		break;


	/* by default i used to block whole /dev directory mount
	 * probably bringing this back.
	 * case OPTION_ALLOW_DEV:
		g_allow_dev = 1;
		break;
	*/


	/*
	 * Bind mount a file from new pod root.
	 */
	case OPTION_FILE:

		if (do_option_bind(params, size, 0))
			return -1;
		break;

	case OPTION_HOME:
		setuid(g_ruid);
		if (do_option_bind(params, size, 1))
			return -1;
		if (setuid(0)) {
			printf("setuid: %s\n", strerror(errno));
			return -1;
		}
		break;


	/* change to bounding set */
	case OPTION_CAP_BSET:

		if (params == NULL) {
			printf("null parameter\n");
			return -1;
		}
		printf("params(%s)\n", params);
		memset(numbuf, 0, sizeof(numbuf));
		strncpy(numbuf, params, sizeof(numbuf)-1);
		if (chop_trailing(numbuf, sizeof(numbuf), '\n'))
			return -1;
		errno = 0;
		read_uint = strtol(numbuf, &err, 10);
		if (*err || errno) {
			printf("allow_cap not an integer\n");
			return -1;
		}
		if (read_uint >= 64) {
			printf("allow_cap too big, v3 supports 64 caps\n");
			return -1;
		}

		printf("cap requested: %d\n", read_uint);
		/*if (is_pcap)
			g_pcaps[read_uint] = 1;
		else*/
			g_fcaps[read_uint] = 1;

		break;

	default:
		break;
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


/* final stage of pod, fix up environment*/
static int post_load()
{
	/* if tracing, we need to whitelist the launcher used to stop process */
	if (g_tracecalls) {
		char opt[256];
		snprintf(opt, sizeof(opt), "rx %s", TRACEE_PATH);
		if (pod_enact_option(OPTION_FILE, opt,
				     strnlen(opt, sizeof(opt)))) {
			printf("error whitelisting tracee program\n");
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
						printf("enact option error\n");
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


	/* done with options, finalize pass */
	if (g_firstpass) {
		return do_chroot_setup();
	}
	else {  /* second pass finished, do the chroot */
		unsigned long remountflags =	  MS_REMOUNT
						| MS_NOSUID
						| MS_NOEXEC
						| MS_NODEV
						| MS_RDONLY;

		if (post_load()) {
			printf("post_load()\n");
			return -1;
		}
		/* some security checks */
		if (pod_process_mountpoints()) {
			printf("mountpoint processing failed\n");
			return -1;
		}

		if (mount(g_chroot_path, g_chroot_path, "bind",
					MS_BIND, NULL)) {
			printf("could not bind mount: %s\n", strerror(errno));
			return -1;
		}
		if (mount(g_chroot_path, g_chroot_path, "bind",
					MS_BIND|remountflags, NULL)) {
			printf("could not bind mount: %s\n", strerror(errno));
			return -1;
		}
		if (mount(NULL, g_chroot_path, NULL, MS_SLAVE|MS_REC, NULL)) {
			printf("could not make slave: %s\n", strerror(errno));
			return -1;
		}

		/* this one may be redundant?
		 * TODO test again, lost the chroot escape code :\ */
		if (chdir(g_chroot_path) < 0) {
			printf("chdir(\"/\") failed: %s\n", strerror(errno));
			return -1;
		}
		/* remount subtree to / */
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








