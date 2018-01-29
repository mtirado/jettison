/* (c) 2015 Michael R. Tirado -- GPLv3, GNU General Public License, version 3.
 * contact: mtirado418@gmail.com
 *
 * pod directories are root owned to prevent ld_preload type shenanigans on
 * programs using file caps. so we need root group for cleanup(chmod g+s).
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
#define MAX_DEPTH 50
#define PLIM 4096

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

static int locate_podpath(char *file)
{
	struct stat st;
	char *pwline, *pwuser;
	int r;

	pwline = passwd_fetchline_byid(g_ruid, PASSWD_FILE);
	if (pwline == NULL) {
		printf("passwd file error\n");
		return -1;
	}
	pwuser = passwd_getfield(pwline, PASSWD_USER);
	if (pwuser == NULL) {
		printf("could not find your username in passwd file\n");
		return -1;
	}

	if (es_sprintf(g_path, sizeof(g_path), NULL, "%s/%s/%s", POD_PATH, pwuser, file))
		return -1;
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
	long rdlong;
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
	rdlong = strtol(argv[3], &err, 10);
	if (err == NULL || *err || errno) {
		printf("bad iteration value\n");
		return -1;
	}
	if (rdlong <= 0) {
		printf("bad iteration count: %li\n", rdlong);
		return -1;
	}
	g_iter = (unsigned int)rdlong;
	return 0;
}


static int proc_checkmounts(char *path)
{
	char *fbuf = NULL;
	size_t fsize;
	size_t fpos = 0;
	unsigned int pathlen;

	errno = 0;
	fsize = (size_t)eslib_procfs_readfile("/proc/mounts", &fbuf);
	if (fsize == (size_t)-1 || fsize == 0) {
		printf("error reading /proc/mounts\n");
		errno = EIO;
		return -1;
	}

	pathlen = strnlen(path, MAX_SYSTEMPATH);
	if (pathlen >= MAX_SYSTEMPATH) {
		printf("path too long\n");
		errno = EINVAL;
		free(fbuf);
		return -1;
	}

	while (fpos < fsize)
	{
		char *line = NULL;
		char *token = NULL;
		unsigned int linepos = 0;
		unsigned int linelen = 0;
		unsigned int advance = 0;

		line = &fbuf[fpos];
		linelen = eslib_string_linelen(line, fsize - fpos);
		if (linelen >= fsize - fpos)
			goto failure;
		if (!eslib_string_is_sane(line, linelen))
			goto failure;
		if (eslib_string_tokenize(line, linelen, " \t"))
			goto failure;

		/* skip first field */
		token = eslib_string_toke(line, linepos, linelen, &advance);
		linepos += advance;
		if (!token)
			goto failure;

		token = eslib_string_toke(line, linepos, linelen, &advance);
		if (!token)
			goto failure;

		/* match anything that starts with path */
		if (strncmp(path, token, pathlen) == 0) {
			printf("mountpoint detected in pod: %s\n", token);
			free(fbuf);
			errno = EEXIST;
			return -1;
		}

		fpos += linelen+1;
		if (fpos > fsize)
			goto failure;
		else if (fpos == fsize)
			break;
	}

	free(fbuf);
	return 0;

failure:
	free(fbuf);
	errno = EIO;
	return -1;
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
#define CHUNK_SIZE 8 /* 8 == 4096 chunk */
unsigned char wbuf[512 * CHUNK_SIZE];
static int overwrite(char *path, unsigned int leaf_action)
{
	blkcnt_t blocks;
	blkcnt_t i;
	int r;
	int testfd;
	struct stat st;
	struct timespec t;
	static unsigned int block_counter = 0;
	unsigned char e1 = 0;

	clock_gettime(CLOCK_MONOTONIC_RAW, &t);
	e1 = (unsigned char)(t.tv_nsec+t.tv_sec);
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

	/* convert blocks to larger chunks */
	blocks = st.st_blocks;
	if (blocks <= 0) /* always write a chunk */
		blocks = CHUNK_SIZE;
	if (blocks % CHUNK_SIZE) /* cover remainder */
		blocks += CHUNK_SIZE - (blocks%CHUNK_SIZE);
	blocks = blocks/CHUNK_SIZE;

	if (leaf_action == ACTION_NUKE)
		printf("nuking ");
	else
		printf("zeroing ");

#if (_FILE_OFFSET_BITS == 64)
	printf("[%lu:%lu] blocks, blocksize: %d\n",
		((unsigned long *)&blocks)[1],
		((unsigned long *)&blocks)[0],
		 sizeof(wbuf));
#elif (_FILE_OFFSET_BITS == 32)
	printf("%lu blocks, blocksize: %d\n", blocks, sizeof(wbuf));
#else
	printf("unknown sizeof(blkcnt_t), blocksize: %d\n" sizeof(wbuf));
#endif

	for (i = 0; i < blocks; ++i )
	{
		if (leaf_action == ACTION_NUKE) {
			unsigned int z;
			for (z = 0; z < sizeof(wbuf); ++z)
			{
				++block_counter;
				e1 = (unsigned char)(e1 + block_counter);
				wbuf[z] = (unsigned char)(wbuf[z] + e1);
				shuffle_bits(wbuf, sizeof(wbuf), wbuf[z], z, e1);
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
int recurse(char *path, unsigned int leaf_action, unsigned int *depth)
{
	char next_path[PLIM];
	struct dirent *dent;
	DIR *dir;

	errno = 0;
	*depth += 1;
	if (*depth >= MAX_DEPTH) {
		printf("path={%s}\n", path);
		errno = ECANCELED;
		return -1;
	}

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
		unsigned int dive = *depth;
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

		if (es_sprintf(next_path, PLIM, NULL, "%s/%s", path, dent->d_name)) {
			printf("truncation error, max is %d: %s\n", PLIM, next_path);
			closedir(dir);
			return -1;
		}
		/* recurse through directories */
		if (dent->d_type == DT_DIR) {
			if (recurse(next_path, leaf_action, &dive)) {
				closedir(dir);
				return -1;
			}
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
		else if (leaf_action == ACTION_RM) {
			if(action(next_path, ACTION_RM)) {
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
	struct timespec t;
	char ch;
	size_t cnt;

	if (getuid() == 0 || geteuid() == 0) {
		printf("WARNING you have uid 0, this is *potentially* disasterous.\n");
		printf("any /proc/mounts we encounter after check will be traversed,\n");
		printf("potentially your root filesystem through a bind mount.\n");
		printf("press y to live dangerously, any other key to exit\n\n");
		if (getch(&ch)) {
			printf("getch error\n");
			return -1;
		}
		if (ch != 'y' && ch != 'Y') {
			printf("aborted\n");
			return 0;
		}
	}

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
		long i, z;
		unsigned char init[]={'v','2','g','i','B','D','e','h','X','W','3','U'};
		long p = (long)getpid();
		for (z = 0; z < (long)sizeof(init); ++z)
		{
			clock_gettime(CLOCK_MONOTONIC_RAW, &t);
			for (i = 0; i < (long)sizeof(wbuf); ++i)
			{
				wbuf[i] = (unsigned char)(wbuf[i]
							+ z+((p+t.tv_nsec)%32));
				wbuf[i] = (unsigned char)(wbuf[i] + i+init[
							(i+z)%((long)sizeof(init)-1)
							]);
			}
		}
	}
	else { /* zero */
		size_t i;
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

	for (cnt = 1; cnt <= g_iter; ++cnt)
	{
		unsigned int depth = 0;
		printf("----------------- pass %d -----------------\n", cnt);
		if (recurse(g_path, g_opts, &depth)) {
			/* TODO: restart with a non-recursive fallback */
			printf("recurse error, try manual cleanup\n");
			if (errno == ECANCELED) {
				printf("maximum depth is %d\n", MAX_DEPTH);
			}
			return -1;
		}
		sync();
	}

	/* unlink files */
	if (g_opts != ACTION_RM) {
		unsigned int depth = 0;
		printf("----------------- unlink -----------------\n");
		if (recurse(g_path, ACTION_RM, &depth)) {
			/* TODO: fallback safe/slow path, and compile time option to
			 * prevent any recursive calls on memory constrained systems
			 */
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
