/* (c) 2015 Michael R. Tirado -- GPLv3, GNU General Public License, version 3.
 * contact: mtirado418@gmail.com
 *
 * pod directories are root owned we, need root privileges for cleanup.
 */

#define _GNU_SOURCE
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <unistd.h>
#include <time.h>
#include "misc.h"
#include "eslib/eslib.h"

/* leaf node actions for recurse function */
#define ACTION_RM     1 /* unlink file */
#define ACTION_ZERO   2 /* zero file */
#define ACTION_NUKE   3 /* destroy */

#define DEBUG_RAND 0

int          g_dbgfile;
uid_t        g_ruid;
unsigned int g_opts;
unsigned int g_iter;
char g_path[MAX_SYSTEMPATH];

static void usage()
{
	printf("\n");
	printf("\n");
	printf("usage:\n");
	printf("\n");
	printf("jettison_destruct <pod_directory> <options>\n");
	printf("\n");
	printf("options:\n");
	printf("\n");
	printf("--zero <n>     zero files\n");
	printf("--nuke <n>     annihilate files\n");
	printf("n is optional iteration count\n");
	printf("\n");
	printf("\n");
	_exit(-1);
}

static int downgrade()
{
	return 0;
}

static int locate_podpath(char *file)
{
	struct stat st;
	char *pwline, *pwuser;
	int r;

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

	snprintf(g_path, sizeof(g_path), "%s/%s/%s", POD_PATH, pwuser, file);
	memset(&st, 0, sizeof(st));
	r = stat(g_path, &st);
	if (r == -1) {
		printf("stat: %s\n", strerror(errno));
		return -1;
	}
	if (!S_ISDIR(st.st_mode)) {
		printf("path is not a directory\n");
		return 1;
	}

	return 0;
}

static int process_arguments(int argc, char *argv[])
{
	unsigned int len;
	char *err = NULL;
	if (argc < 2) {
		usage();
		return -1;
	}
	g_opts  = 0;
	g_iter  = 1;
	memset(g_path, 0, sizeof(g_path));

	if (locate_podpath(argv[1])) {
		printf("could not locate pod (check filename)\n");
		return -1;
	}

	if (argc == 2) {
		g_opts = ACTION_RM;
		return 0;
	}

	/* check options */
	len = strnlen(argv[2], 32);
	if (len == 0 || len >= 32) {
		usage();
		return -1;
	}
	if (strncmp(argv[2], "--zero", len) == 0) {
		g_opts = ACTION_ZERO;
	}
	else if (strncmp(argv[2], "--nuke", len) == 0) {
		g_opts = ACTION_NUKE;
	}
	else {
		usage();
		return -1;
	}

	if (argc == 3)
		return 0;

	len = strnlen(argv[3], 32);
	if (len == 0 || len >= 32) {
		usage();
		return -1;
	}

	/* check iteration count */
	errno = 0;
	g_iter = strtol(argv[3], &err, 10);
	if (err == NULL || *err || errno) {
		printf("bad iteration value\n");
		return -1;
	}
	if (g_iter == 0)
		g_iter = 1;

	return 0;
}


static int proc_checkmounts(char *path)
{
	char *fbuf;
	off_t fsize;
	off_t cur, start, end;
	unsigned int len, pathlen;
	errno = 0;
	fsize = eslib_procfs_readfile("/proc/mounts", &fbuf);
	if (fsize == -1) {
		printf("error reading /proc/mounts\n");
		errno = EIO;
		return -1;
	}
	else if (fsize == 0 || fbuf == NULL) {
		printf("/proc/mounts is empty\n");
		errno = ESRCH;
		return -1;
	}
	pathlen = strnlen(path, MAX_SYSTEMPATH);
	if (pathlen >= MAX_SYSTEMPATH) {
		printf("path too long\n");
		errno = EINVAL;
		return -1;
	}

	cur = 0;
	while (1)
	{
		start = cur;
		/* seek to separator */
		while (fbuf[start] != ' ' && fbuf[start] != '\t')
		{
			if (++start >= fsize) {
				printf("/proc/mounts error1\n");
				goto failure;
			}
		}
		/* handle potentially  repeating separator */
		while (fbuf[start] == ' ' || fbuf[start] == '\t')
		{
			if (++start >= fsize) {
				printf("/proc/mounts error2\n");
				goto failure;
			}
		}
		/* get end of field 2 */
		end = start;
		while (fbuf[end] != ' ' && fbuf[end] != '\t')
		{
			if (++end >= fsize) {
				printf("/proc/mounts error3\n");
				goto failure;
			}
		}
		len = end-start;
		if (len >= MAX_SYSTEMPATH-1) {
			printf("mountpoint path is too long\n");
			goto failure;
		}

		/* match anything that starts with path */
		if (strncmp(path, &fbuf[start], pathlen) == 0) {
			fbuf[end] = '\0';
			printf("mountpoint detected in pod: %s\n", &fbuf[start]);
			free(fbuf);
			errno = EEXIST;
			return -1;
		}
		/* go to next line */
		while(fbuf[end] != '\n')
		{
			if (++end >= fsize) {
				goto not_found;
			}
		}
		/* consume trailing newlines */
		while(fbuf[end] == '\n')
		{
			if (++end >= fsize) {
				goto not_found;
			}
		}
		cur = end;
	}

failure:
	free(fbuf);
	errno = EIO;
	return -1;

not_found:
	free(fbuf);
	return 0;
}


static int unlink_file(char *path)
{
	printf("unlinking: %s\n", path);
	if (unlink(path)) {
		printf("unlink(%s): %s\n", path, strerror(errno));
		return -1;
	}
	return 0;
}

unsigned char wbuf[512 * 8]; /* 4096 */
static int overwrite(char *path, unsigned int leaf_action)
{
	int testfd, r;
	blkcnt_t  blocks, i;
	struct stat st;
	struct timespec t;
	static unsigned int block_total = 0;
	unsigned int e1 = 0;

	clock_gettime(CLOCK_MONOTONIC_RAW, &t);
	e1 = t.tv_nsec;
	memset(&st, 0, sizeof(st));
	r = stat(path, &st);
	if (r == -1) {
		printf("stat: %s\n", strerror(errno));
		return -1;
	}

	testfd = open(path, O_RDWR, 0750);
	if (testfd == -1) {
		printf("overwrite open(%s): %s\n", path, strerror(errno));
		return 0;
	}

	if (lseek(testfd, SEEK_SET, 0)) {
		printf("lseek: %s\n", strerror(errno));
		close(testfd);
		return -1;
	}

	/* convert blocks to 4096 byte chunks */
	blocks = st.st_blocks; /* 512 byte blocks */
	if (blocks <= 0) /* always write a chunk */
		blocks = 8;
	if (blocks % 8) /* cover remainder */
		blocks += 8 - (blocks%8);
	blocks = blocks/8;

	if (leaf_action == ACTION_NUKE)
		printf("nuking %lu blocks, blocksize: %d\n", blocks, sizeof(wbuf));
	else
		printf("zeroing %lu blocks, blocksize: %d\n", blocks, sizeof(wbuf));

	for (i = 0; i < blocks; ++i)
	{
		if (leaf_action == ACTION_NUKE) {
			unsigned int z, x;
			for (z = 0; z < sizeof(wbuf); ++z)
			{
				++block_total;
				e1 += block_total;
				wbuf[z] += e1;
				for (x = 1; x <= 2; ++x)
				{
					shuffle_bits(wbuf, sizeof(wbuf), z, x, e1);
				}
			}
		}
do_wrover:
		r = write(testfd, wbuf, sizeof(wbuf));
		if (r == -1 && (errno == EAGAIN || errno == EINTR)) {
			goto do_wrover;
		}
		else if (r != sizeof(wbuf)) {
			printf("write(%d,%d): %s\n", r, (int)i, strerror(errno));
			close(testfd);
			return -1;
		}
#if DEBUG_RAND
do_dbgwrover:
		r = write(g_dbgfile, wbuf, sizeof(wbuf));
		if (r == -1 && (errno == EAGAIN || errno == EINTR)) {
			goto do_dbgwrover;
		}
		else if (r != sizeof(wbuf)) {
			printf("write(%d,%d): %s\n", r, (int)i, strerror(errno));
			close(testfd);
			return -1;
		}
#endif
	}

	close(testfd);
	return 0;
}


static int action(char *path, unsigned int leaf_action)
{
	switch (leaf_action)
	{
		case ACTION_RM:
			return unlink_file(path);
		case ACTION_ZERO:
		case ACTION_NUKE:
			return overwrite(path, leaf_action);
		default:
			break;
	}
	return -1;
}

/* traverse directory tree */
int recurse(char *path, unsigned int leaf_action)
{
	char next_path[MAX_SYSTEMPATH];
	struct dirent *dent;
	DIR *dir;

	dir = opendir(path);
	if (dir == NULL) {
		printf("error opening dir %s: %s\n", path, strerror(errno));
		return 0;
	}
#if DEBUG_RAND
	printf("recurse(%d) path: %s\n", leaf_action, path);
#endif
	while (1)
	{
		dent = readdir(dir);
		if (dent == NULL) {
			break;
		}
		/* ignore . and .. */
		if (dent->d_name[0] == '.') {
			if (dent->d_name[1] == '\0') {
				continue;
			}
			else if (dent->d_name[1] == '.') {
				if (dent->d_name[2] == '\0')
					continue;
			}
		}

		snprintf(next_path, sizeof(next_path), "%s/%s", path, dent->d_name);
		/* recurse through directories */
		if (dent->d_type == DT_DIR) {
			recurse(next_path, leaf_action);
			if (leaf_action == ACTION_RM) {
				printf("rmdir(%s)\n", next_path);
				if (rmdir(next_path)) {
					printf("rmdir failed: %s\n", strerror(errno));
				}
			}
		}
		else if (dent->d_type == DT_REG) {
			if(action(next_path, leaf_action)) {
				closedir(dir);
				_exit(-1);
			}
		}
	}
	closedir(dir);
	return 0;
}

int main(int argc, char *argv[])
{
	unsigned int i;
	struct timespec t;
	char ch;

	if (downgrade())
		return -1;
#if DEBUG_RAND
	g_dbgfile = open("./randout", O_RDWR|O_TRUNC|O_CREAT, 0750);
	if (g_dbgfile == -1) {
		printf("dbg file open: %s\n", strerror(errno));
		return -1;
	}
#endif
	g_ruid = getuid();

	if (process_arguments(argc, argv))
		return -1;

	printf("\ntarget: %s\n", g_path);
	printf("DESTROY? (y/n)\n");
	if (getch(&ch)) {
		printf("getch error\n");
		return -1;
	}
	if (ch != 'y' && ch != 'Y') {
		printf("aborted\n");
		return 0;
	}

	/* note: rng assumes overflows are not saturated! */
	if (g_opts == ACTION_NUKE) {
		unsigned int z;
		unsigned char init[]={'v','2','g','i','B','D','e','h','X','W','3','U'};
		unsigned int p = getpid();
		for (z = 0; z < sizeof(init); ++z)
		{
			clock_gettime(CLOCK_MONOTONIC_RAW, &t);
			for (i = 0; i < sizeof(wbuf); ++i)
			{
				wbuf[i] += z+((p+t.tv_nsec)%32);
				wbuf[i] += i+init[(i+z)%(sizeof(init)-1)];
			}
		}
	}
	else { /* zero */
		memset(wbuf, 0, sizeof(wbuf));
		for (i = 0; i < sizeof(wbuf); ++i)
		{
			if (wbuf[i] != 0) {
				/* does this actually happen? */
				printf("memset was optimized out?\n");
				return -1;
			}
		}
	}

	 /* make sure no mounts are in pod path */
	if (proc_checkmounts(g_path)) {
		printf("you must unmount before we can continue.\n");
		return -1;
	}

	for (i = 1; i <= g_iter; ++i)
	{
		printf("----------------- pass %d -----------------\n", i);
		if (recurse(g_path, g_opts)) {
			printf("recurse error, try manual cleanup\n");
			return -1;
		}
		sync(); /* flush cache to device */
	}

	/* unlink files */
	if (g_opts != ACTION_RM) {
		printf("----------------- unlink -----------------\n");
		if (recurse(g_path, ACTION_RM)) {
			printf("recurse error, try manual cleanup\n");
			return -1;
		}
	}

	/* remove pod dir */
	if (rmdir(g_path)) {
		printf("rmdir: %s\n", strerror(errno));
		return -1;
	}
	return 0;
}
