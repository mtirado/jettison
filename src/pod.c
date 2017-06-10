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
#include "eslib/eslib.h"
#include "eslib/eslib_fortify.h"
#include "eslib/eslib_rtnetlink.h"

#define is_whitespace(chr) (chr == ' ' || chr == '\t')
#define MAX_PODCFG (1024 * 10)

#ifdef X11OPT
	#include <X11/Xauth.h>
#endif

extern char **environ;

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

struct path_node *g_mountpoints;

/* external variables from jettison.c
 * non-jettison.c C callers will have to define these.
 */
extern gid_t g_rgid;
extern uid_t g_ruid;

/* much globals,
 * TODO make struct and move into eslib as a generic config file parser */
char g_filedata[MAX_PODCFG+1]; /* + terminator/eof */
size_t g_filesize;
int g_useblacklist;
unsigned int g_podflags;
int g_fcaps[NUM_OF_CAPS];
char g_chroot_path[MAX_SYSTEMPATH];
char g_errbuf[ESLIB_LOG_MAXMSG];

struct newnet_param *g_podnewnet;
struct user_privs *g_podprivs;
struct seccomp_program *g_podseccfilter;

static int pod_load_config_pass1(char *data, size_t size);
static int pod_load_config_pass2(char *data, size_t size);
static int pod_enact_option(unsigned int option, char *params, size_t size, int pass);

/* home root is a special case since eslib considers / to be an invalid path */
struct path_node *g_homeroot;

#define KWLEN  32 /* maximum string length */
const char keywords[KWCOUNT][KWLEN] = {

	"newnet",        /* create new network namespace */
	"newpts",        /* creates a new /dev/pts instance */
	"noproc",        /* do not mount /proc */
	"home_exec",     /* mount empty home dir with exec flag */
	"tmp_exec",      /* mount /tmp dir with exec flag */
#ifdef X11OPT
	"x11",           /* bind mount X11 socket and generate auth file */
#endif

	"- - - - - - -", /* cutoff for podflags, disregard */

	"seccomp_allow", /* add a syscall to seccomp whitelist.
			       otherwise, everything is allowed. */
	"seccomp_block", /* block syscall without sigkill (if using --strict) */
	"file",          /* bind mount file with options w,r,x,d,s */
	"home",          /* ^  -- but $HOME/file is rooted in /podhome  */
	"capability",    /* leave capability in bounding set */
	"machine-id"     /* specify or generate a /etc/machine-id string */
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
	memset(g_filedata, 0, sizeof(g_filedata));
	free_pathnodes();
	return 0;
}

/*
 * get $HOME string from environment, could make this optional to read
 * from /etc/passwd instead of letting user set it from environment.
 */
static char *gethome()
{
	static char static_home[MAX_SYSTEMPATH];
	static int once = 0;
	char *path = NULL;
	int r;
	ino_t root_ino;
	ino_t file_ino;
	unsigned int len;
	uid_t fuid;

	if (once) {
		return static_home;
	}

	path = eslib_proc_getenv("HOME");
	if (path == NULL) {
		printf("could not find $HOME environment variable\n");
		return NULL;
	}

	len = strnlen(path, MAX_SYSTEMPATH);
	if (len >= MAX_SYSTEMPATH || len == 0)
		goto bad_path;
	if (chop_trailing(path, MAX_SYSTEMPATH, '/') < 0)
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
	strncpy(static_home, path, MAX_SYSTEMPATH-1);
	static_home[MAX_SYSTEMPATH-1] = '\0';
	once = 1;
	return static_home;

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
int pod_prepare(char *filepath, char *chroot_path, struct newnet_param *newnet,
		struct seccomp_program *seccfilter, unsigned int blacklist,
		struct user_privs *privs, unsigned int *outflags)
{
	int r;
	FILE *file;
	struct stat st;

	if (chroot_path == NULL || outflags == NULL || seccfilter == NULL
			|| filepath == NULL || newnet == NULL || privs == NULL)
		return -1;

	if (MAX_SYSTEMPATH < 256) {
		printf("MAX_SYSTEMPATH is too small (<256)\n");
		return -1;
	}

	g_podflags = 0;
	g_homeroot = NULL;
	g_mountpoints = NULL;
	memset(g_fcaps, 0, sizeof(g_fcaps));
	memset(g_filedata, 0, sizeof(g_filedata));
	memset(g_chroot_path, 0, sizeof(g_chroot_path));
	g_podnewnet = newnet;
	g_podseccfilter = seccfilter;
	g_useblacklist = blacklist;
	g_podprivs = privs;

	/* check chroot path */
	if (strnlen(chroot_path, MAX_SYSTEMPATH) >= MAX_SYSTEMPATH-100) {
		printf("chroot path too long: %s\n", chroot_path);
		return -1;
	}
	if (eslib_file_path_check(chroot_path)) {
		printf("bad chroot path\n");
		return -1;
	}
	r = stat(chroot_path, &st);
	if (r == 0) {
		if (!S_ISDIR(st.st_mode)) {
			printf("chroot path(%s) is not a directory\n", chroot_path);
			return -1;
		}
		if (st.st_uid != 0 || st.st_gid != 0) {
			printf("chroot path(%s) must be owned by root\n", chroot_path);
			return -1;
		}
	}
	else if (r == -1 && errno == ENOENT) {
		if (mkdir(chroot_path, 0770)) {
			printf("chroot path(%s) couldn't be created\n", chroot_path);
			return -1;
		}
		if (chmod(chroot_path, 0770)) {
			printf("chmod(%s): %s\n", chroot_path, strerror(errno));
			return -1;
		}
	}
	else {
		printf("stat: %s\n", strerror(errno));
		return -1;
	}

	file = get_configfile(filepath);
	if (file == NULL) {
		printf("could not read pod configuration file: %s\n", filepath);
		return -1;
	}

	printf("chroot path: %s\r\n", chroot_path);
	strncpy(g_chroot_path, chroot_path, MAX_SYSTEMPATH-1);

	/* read config file */
	fseek(file, 0, SEEK_END);
	g_filesize = ftell(file);
	fseek(file, 0, SEEK_SET);
	if (g_filesize >= MAX_PODCFG || g_filesize == 0) {
		printf("file size error\n");
		goto err_close;
	}

	if (fread(g_filedata, 1, g_filesize, file) != g_filesize){
		goto err_free_close;
	}
	fclose(file);
	g_filedata[g_filesize] = '\0';

	/* first pass, copy out podflags */
	r = pod_load_config_pass1(g_filedata, g_filesize);
	if (r) {
		pod_free();
		return -1;
	}

	*outflags = g_podflags;
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
		if (eslib_file_mkdirpath(g_chroot_path, 0775)) {
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
	setuid(0);
	setgid(0);
	if (chown(g_chroot_path, 0, 0)) {
		printf("chown %s failed: %s\n", g_chroot_path, strerror(errno));
		return -1;
	}
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
			if (eslib_file_mkdirpath(dest, 0775)  == -1) {
				snprintf(g_errbuf, sizeof(g_errbuf),
					"prep_bind mkdir failed: %s", dest);
				eslib_logerror("jettison", g_errbuf);
				return -1;
			}
		}
		else {
			if (eslib_file_mkfile(dest, 0775) == -1) {
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
		if (c == ' ' || c == '\t' || c == '\0') {
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
	if (chop_trailing(path, MAX_SYSTEMPATH, '/') < 0)
		return -1;

	if (eslib_file_path_check(path)) {
		printf("bad path\n");
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
	printf("bad file param (rwxsdR flags) \n");
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
	if (len >= MAX_SYSTEMPATH || len == 0)
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

char x11display_number[32];
char *x11get_displaynum(char *display, unsigned int *outlen)
{
	char *start = NULL;
	char *cur = NULL;
	unsigned int len = 0;

	if (!display || !outlen)
		return NULL;

	memset(x11display_number, 0, sizeof(x11display_number));
	*outlen = 0;


	/* extract xauth display number from env var */
	start = display;
	if (*start != ':')
		goto disp_err;
	cur = ++start;
	while(1)
	{
		if (*cur == '.' || *cur == '\0')
			break;
		else if (*cur < '0' || *cur > '9')
			goto disp_err;
		++cur;
	}
	len = cur - start;
	if (len == 0)
		goto disp_err;
	else if (len >= sizeof(x11display_number) - 1)
		goto disp_err;

	strncpy(x11display_number, start, len);
	x11display_number[len] = '\0';
	*outlen = len;
	return x11display_number;

disp_err:
	printf("problem with display environment variable\n");
	printf("jettison only supports simple display number -- DISPLAY=:0\n");
	return NULL;
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

	setuid(g_ruid);

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

	if (xauth_file != NULL) {
		if (eslib_file_path_check(xauth_file)) {
			printf("XAUTHORITY bad path\n");
			return -1;
		}
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
					XauDisposeAuth(xau);
					goto fail_close;
				}
				found = 1;
			}
			XauDisposeAuth(xau);

		}
		fclose(fin);
		fclose(fout);
	}
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
	if (g_podnewnet->active) {
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
		g_podnewnet->kind = ESRTNL_KIND_UNKNOWN;
	else if (strncmp(type, "loop", 5) == 0)
		g_podnewnet->kind = ESRTNL_KIND_LOOP;
#ifdef NEWNET_VETHBR
	/* TODO !!! */
	else if (strncmp(type, "vethbr", 7) == 0)
		g_podnewnet->kind = ESRTNL_KIND_VETHBR;
#endif
#ifdef NEWNET_IPVLAN
	else if (strncmp(type, "ipvlan", 7) == 0)
		g_podnewnet->kind = ESRTNL_KIND_IPVLAN;
#endif
#ifdef NEWNET_MACVLAN
	else if (strncmp(type, "macvlan", 8) == 0)
		g_podnewnet->kind = ESRTNL_KIND_MACVLAN;
#endif

	switch (g_podnewnet->kind)
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
		if (devlen == 0 || devlen >= sizeof(g_podnewnet->dev)) {
			printf("bad master devlen: %d\n", devlen);
			return -1;
		}
		strncpy(g_podnewnet->dev, &params[z], devlen);

		/* read hwaddr string */
		if (g_podnewnet->kind == ESRTNL_KIND_MACVLAN) {
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
			if (addrlen == 0 || addrlen >= sizeof(g_podnewnet->hwaddr)) {
				printf("bad hwaddr: %d\n", addrlen);
				return -1;
			}
			strncpy(g_podnewnet->hwaddr, &params[z], addrlen);
		}

		/* read ipaddr string */
		z = ++i;
		for (; i < size; ++i)
			if (params[i] == ' ' || params[i] == '\0')
				break;
		addrlen = i - z;
		if (addrlen == 0 || addrlen >= sizeof(g_podnewnet->addr)) {
			printf("bad addr: %d\n", addrlen);
			return -1;
		}
		strncpy(g_podnewnet->addr, &params[z], addrlen);

		/* does addr have subnet mask? */
		for (i = 0; i < addrlen; ++i) {
			if (g_podnewnet->addr[i] == '/') {
				char *err = NULL;
				long netmask;
				g_podnewnet->addr[i] = '\0';
				if (++i >= addrlen) { /* slash was last char */
					printf("bad subnet mask\n");
					return -1;
				}
				errno = 0;
				netmask = strtol(&g_podnewnet->addr[i], &err, 10);
				if (err == NULL || *err || errno) {
					printf("bad subnet mask value\n");
					return -1;
				}
				if (netmask < 0 || netmask > 32) {
					printf("invalid netmask\n");
					return -1;
				}
				g_podnewnet->netmask = netmask;
				strncpy(g_podnewnet->prefix, &g_podnewnet->addr[i], 2);
				g_podnewnet->prefix[2] = '\0';
				break;
			}
		}
		if (i >= addrlen) {
			snprintf(g_podnewnet->prefix, 3, "%d", DEFAULT_NETMASK_PREFIX);
			g_podnewnet->netmask = DEFAULT_NETMASK_PREFIX;
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

	g_podnewnet->active = 1;
	return 0;
}

static int load_seccomp_blacklist(char *file)
{
	syscall_list_clear(&g_podseccfilter->white);
	if (syscall_list_loadfile(&g_podseccfilter->black, file)) {
		printf("could not load blacklist %s\n", file);
		return -1;
	}
	return 0;
}

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
	case OPTION_X11:
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
static int pod_enact_option(unsigned int option, char *params, size_t size, int pass)
{

	char src[MAX_SYSTEMPATH];
	char dest[MAX_SYSTEMPATH];
	char path[MAX_SYSTEMPATH];
	char syscall_buf[MAX_SYSCALL_NAME];
	int  r;
#ifdef USE_FILE_CAPS
	int  cap_nr;
	char cap_buf[MAX_CAP_NAME];
#endif
	if (option >= KWCOUNT)
		return -1;

	/* first pass happens before we clone */
	if (pass == 1)
		return pod_enact_option_pass1(option, params, size);
	else if (pass != 2)
		return -1;

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
	case OPTION_TMP_EXEC:
	case OPTION_NEWNET:
	case OPTION_NEWPTS:
		break;

	/* add a systemcall to the whitelist */
	case OPTION_SECCOMP_ALLOW:
		if (g_useblacklist)
			break;

		if (params == NULL) {
			printf("null parameter\n");
			return -1;
		}
		if (size >= MAX_SYSCALL_NAME) {
			printf("seccomp_allow syscall name too long.\n");
			return -1;
		}
		memset(syscall_buf, 0, sizeof(syscall_buf));
		strncpy(syscall_buf, params, MAX_SYSCALL_NAME);
		if (syscall_list_addname(&g_podseccfilter->white, syscall_buf)) {
			printf("add syscall white error: %s\n", syscall_buf);
			printf("not found or reached max syscalls(%d)\n", MAX_SYSCALLS);
			return -1;
		}
		break;

	/* add a systemcall to the blocklist */
	case OPTION_SECCOMP_BLOCK:
		if (g_useblacklist)
			break;

		if (params == NULL) {
			printf("null parameter\n");
			return -1;
		}
		if (size >= MAX_SYSCALL_NAME) {
			printf("seccomp_block syscall name too long.\n");
			return -1;
		}
		memset(syscall_buf, 0, sizeof(syscall_buf));
		strncpy(syscall_buf, params, MAX_SYSCALL_NAME);
		if (syscall_list_addname(&g_podseccfilter->black, syscall_buf)) {
			printf("add syscall block error: %s\n", syscall_buf);
			printf("not found or reached max syscalls(%d)\n", MAX_SYSCALLS);
			return -1;
		}
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
		if (size >= MAX_CAP_NAME) {
			printf("cap name too long\n");
			return -1;
		}
		strncpy(cap_buf, params, MAX_CAP_NAME-1);
		cap_buf[MAX_CAP_NAME-1] = '\0';

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
			if (eslib_file_mkfile(path, 0775)) {
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
			if (create_machineid(path, NULL, 0x5f5f5f5f
							+(unsigned int)t.tv_nsec
							+(unsigned int)t.tv_sec)) {
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
#endif

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
	/* make tmp dir */
	snprintf(pathbuf, sizeof(pathbuf), "%s/tmp", g_chroot_path);
	mkdir(pathbuf, 0770);

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
	if (g_podflags & (1 << OPTION_TMP_EXEC)) {
		tnode.mntflags &= ~MS_NOEXEC;
	}
	if (pathnode_bind(&tnode)) {
		printf("pathnode_bind(%s, %s) failed\n", tnode.src, tnode.dest);
		return -1;
	}

	/* hookup new pts instance */
	if (g_podflags & (1 << OPTION_NEWPTS)) {
		if (g_podprivs->newpts == 0) {
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

			eslib_file_mkfile(tnode.dest, 0775);
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
		snprintf(dest, MAX_SYSTEMPATH, "%s/dev", g_chroot_path);
		mkdir(dest, 0755);
		chmod(dest, 0755);
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
	if (g_podflags & (1<<OPTION_X11)) {
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

	/* overrides pod file seccomp list with a systemwide blacklist */
	if (g_useblacklist) {
		if (load_seccomp_blacklist(JETTISON_BLACKLIST)) {
			return -1;
		}
	}
	return 0;
}

static int get_keyword(char *kw)
{
	unsigned int i = 0;

	for (; i < KWCOUNT; ++i)
	{
		if (strncmp(keywords[i], kw, KWLEN) == 0)
			return i;
	}
	return -1;
}
static int check_line(char *lnbuf, const size_t len)
{
	size_t i;
	for (i = 0; i < len; ++i)
	{
		if (lnbuf[i] < 32 || lnbuf[i] > 126) {
			if (lnbuf[i] != '\t' && lnbuf[i] != '\n') {
				printf("invalid character(%d)\n", lnbuf[i]);
				return -1;
			}
		}
	}
	return 0;
}

/* prepare keyword with parameters, return start of next line
 * len does not include newline */
static char *cfg_parse_line(char *lnbuf, const size_t len, int pass)
{
	char *eol = lnbuf + len;
	char *kw_end;
	char *param_start;
	int kw;

	if (len == 0 || lnbuf[0] == '#')
		return eol;

	if (check_line(lnbuf, len))
		return NULL;

	/* find keyword end */
	for (kw_end = lnbuf; kw_end < eol; ++kw_end)
	{
		char c = *kw_end;
		if (is_whitespace(c)) {
			*kw_end = '\0'; /* insert terminator */
			break;
		}
	}
	if (kw_end > eol) {
		return NULL;
	}

	/* get keyword */
	kw = get_keyword(lnbuf);
	if (kw < 0) {
		printf("unknown keyword %s\n", lnbuf);
		return NULL;
	}

	/* no parameters */
	if (kw_end == eol) {
		if (pod_enact_option(kw, NULL, 0, pass))
			return NULL;
		return eol;
	}

	/* find parameter start */
	for (param_start = kw_end+1; param_start < eol; ++param_start)
	{
		char c = *param_start;
		if (!is_whitespace(c)) {
			break; /* start here */
		}
	}
	if (param_start >= eol) {
		printf("cannot find parameters\n");
		return NULL;
	}

	if (pod_enact_option(kw, param_start, eol - param_start, pass))
		return NULL;

	return eol;
}

static int cfg_parse_config(char *fbuf, const size_t fsize, int pass)
{
	char buf[MAX_PODCFG];
	const char *eof = buf + fsize;
	char *scan;
	unsigned int line_number = 1;

	if (fsize == 0 || fsize >= sizeof(buf)) {
		printf("bad config file size\n");
		return -1;
	}

	memset(buf, 0, sizeof(buf));
	memcpy(buf, fbuf, fsize);

	for (scan = buf; scan < eof; ++scan)
	{
		char *eol = scan;
		char *start = scan;
		size_t len = 0;

		while (*eol != '\n')
		{
			if (++len >= MAX_PODCFG) {
				printf("config size exceeds %d\n", MAX_PODCFG-1);
				return -1;
			}
			if (++eol >= eof) {
				break;
			}
		}
		/* inserts null terminator after keyword */
		*eol = '\0';
		scan = cfg_parse_line(start, len, pass);
		if (scan == NULL) {
			printf(">>> line number: %d\n", line_number);
			return -1;
		}
		++line_number;
	}
	return 0;
}

static int pod_load_config_pass1(char *data, size_t size)
{
	if (cfg_parse_config(data, size, 1)) {
		return -1;
	}
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

static int pod_load_config_pass2(char *data, size_t size)
{  /* second pass finished, do binds and chroot */
	int r;
	struct path_node *n;
	unsigned long remountflags =	  MS_REMOUNT
					| MS_NOSUID
					| MS_NOEXEC
					| MS_NODEV
					| MS_RDONLY
					| MS_UNBINDABLE;

	if (cfg_parse_config(data, size, 2)) {
		printf("parse_config_pass2\n");
		return -1;
	}

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

	return 0;
}

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
	r = pod_load_config_pass2(g_filedata, g_filesize);
	if (r < 0) {
		printf("pod_load_config(2) error\n");
		goto err_free;
	}
	if (chmod("/tmp", 01777)) {
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

