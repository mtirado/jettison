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
#include "misc.h"

/* leaf node actions for recurse function */
#define ACTION_RM    1 /* unlink file */
#define ACTION_ZERO  2 /* zero file */
#define ACTION_NUKE  3 /* destroy */

uid_t 	     g_ruid;
unsigned int g_opts;
unsigned int g_iter;
char g_path[MAX_SYSTEMPATH];

static void usage()
{
	printf("usage:\n");
	printf("\n");
	printf("jettison_destruct <pod_directory> <options>\n");
	printf("\n");
	printf("options:\n");
	printf("\n");
	printf("--zero <n>     zero files\n");
	printf("--nuke <n>     annihilate files\n");
	printf("n is optional iteration count\n");
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
	g_opts = 0;
	g_iter = 1;
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
	printf("unlink: %s\n", path);
	return 0;
}

char zeros[4096 * 10];
static int zero(char *path)
{
	int testfd, r;
	blksize_t bksize;
	blkcnt_t  blocks, i;
	struct stat st;

	printf("zorro: %s\n", path);

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
	if ((size_t)bksize > sizeof(zeros))
		bksize = sizeof(zeros);

	printf("zeroing %lu blocks, blocksize: %lu\n", blocks, bksize);
	for (i = 0; i < blocks; ++i)
	{
do_over:
		r = write(testfd, zeros, bksize);
		if (r == -1 && (errno == EAGAIN || errno == EINTR)) {
			goto do_over;
		}
		else if (r < 1) {
			printf("write(%d,%d): %s\n", r, (int)i, strerror(errno));
			close(testfd);
			return -1;
		}
	}

	close(testfd);
	return 0;
}

static int nuke(char *path)
{
	printf("annihilate: %s\n", path);
	return 0;
}

static int action(char *path, unsigned int leaf_action)
{
	switch (leaf_action)
	{
		case ACTION_RM:
			return unlink_file(path);
		case ACTION_ZERO:
			return zero(path);
		case ACTION_NUKE:
			return nuke(path);
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
		return -1;
	}
	printf("recurse(%d) path: %s\n", leaf_action, path);
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
		/*
		 * for each file run specified action, for each directory
		 * call recurse again.
		 */
		snprintf(next_path, sizeof(next_path), "%s/%s", path, dent->d_name);
		/* recurse through directories */
		if (dent->d_type == DT_DIR) {
			recurse(next_path, leaf_action);
			rmdir(next_path);
			continue;
		}
		/* take action on other files */
		if (action(next_path, leaf_action)) {
			printf("file error: %s\n", next_path);
			g_iter = 0;
			closedir(dir);
			_exit(-1);
			return -1;
			return -1;
		}
       	}
	closedir(dir);
	return 0;
}

int main(int argc, char *argv[])
{
	unsigned int i;
	if (downgrade())
		return -1;

	g_ruid = getuid();
	printf("destruct uid: %d\n", g_ruid);

	if (process_arguments(argc, argv))
		return -1;

	memset(zeros, 0, sizeof(zeros));
	for (i = 0; i < sizeof(zeros); ++i) {
		if (zeros[i] != 0) {
			/* does this actually happen? */
			printf("memset was optimized out?\n");
			return -1;
		}
	}

	for (i = 0; i < g_iter; ++i)
	{
		printf("----------------- pass %d -----------------\n", i);
		if (recurse(g_path, g_opts)) {
			printf("recurse error, try manual cleanup\n");
			return -1;
		}
	}

	if (g_opts != ACTION_RM) {
		/* unlink files too */
		printf("----------------- unlink -----------------\n");
		if (recurse(g_path, ACTION_RM)) {
			printf("recurse error, try manual cleanup\n");
			return -1;
		}
	}
	printf("destructed\n");
	return 0;
}
