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

/* leaf node actions for recurse function */
#define ACTION_RM     1 /* unlink file */
#define ACTION_ZERO   2 /* zero file */
#define ACTION_NUKE   3 /* destroy */

#define DEBUG_RAND 1

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

static int unlink_file(char *path)
{
	return 0;
	printf("unlink: %s\n", path);
	/* TODO  XXX XXX XXX */
	if (unlink(path)) {
		printf("unlink(%s): %s\n", path, strerror(errno));
		return -1;
	}
	return 0;
}

unsigned char wbuf[4096 * 10];
static int overwrite(char *path, unsigned int leaf_action)
{
	int testfd, r;
	blksize_t bksize;
	blkcnt_t  blocks, i;
	struct stat st;
	struct timespec t;
	unsigned int block_total;
	unsigned int e1 = 0;

	clock_gettime(CLOCK_MONOTONIC_RAW, &t);

	memset(&st, 0, sizeof(st));
	r = stat(path, &st);
	if (r == -1) {
		printf("stat: %s\n", strerror(errno));
		return -1;
	}

	if (st.st_blocks <= 0) {
		st.st_blocks = 1;
	}

	testfd = open("./testfile", O_RDWR|O_CREAT|O_TRUNC, 0750);
	if (testfd == -1) {
		printf("open: %s\n", strerror(errno));
		return -1;
	}

	if (lseek(testfd, SEEK_SET, 0)) {
		printf("lseek: %s\n", strerror(errno));
		close(testfd);
		return -1;
	}

	blocks = st.st_blocks;
	bksize = st.st_blksize;
	if ((size_t)bksize > sizeof(wbuf)) {
		bksize = sizeof(wbuf);
	}

#if DEBUG_RAND
	printf("writing %lu blocks, blocksize: %lu\n", blocks, bksize);
#endif
	block_total = 0;
	for (i = 0; i < blocks; ++i)
	{
		if (leaf_action == ACTION_NUKE) {
			unsigned int z;
			for (z = 0; z < (unsigned int)bksize; ++z)
			{
				++block_total;
				e1 ^= block_total;
				wbuf[z] += e1;
			}
		}
do_wrover:
		r = write(testfd, wbuf, bksize);
		if (r == -1 && (errno == EAGAIN || errno == EINTR)) {
			goto do_wrover;
		}
		else if (r != bksize) {
			printf("write(%d,%d): %s\n", r, (int)i, strerror(errno));
			close(testfd);
			return -1;
		}
#if DEBUG_RAND
do_dbgwrover:
		r = write(g_dbgfile, wbuf, bksize);
		if (r == -1 && (errno == EAGAIN || errno == EINTR)) {
			goto do_dbgwrover;
		}
		else if (r != bksize) {
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
			rmdir(next_path);
			continue;
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
	printf("destruct uid: %d\n", g_ruid);

	if (process_arguments(argc, argv))
		return -1;


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
				/* XXX does this actually happen? */
				printf("memset was optimized out?\n");
				return -1;
			}
		}
	}

	for (i = 0; i < g_iter; ++i)
	{
		printf("----------------- pass %d -----------------\n", i);
		if (recurse(g_path, g_opts)) {
			printf("recurse error, try manual cleanup\n");
			return -1;
		}
		sync();
	}

	/* unlink files */
	if (g_opts != ACTION_RM) {
		printf("----------------- unlink -----------------\n");
		if (recurse(g_path, ACTION_RM)) {
			printf("recurse error, try manual cleanup\n");
			return -1;
		}
	}
	return 0;
}
