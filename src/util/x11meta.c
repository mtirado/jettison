/* (c) 2015 Michael R. Tirado -- GPLv3, GNU General Public License, version 3.
 * contact: mtirado418@gmail.com
 *
 * sandboxes user owned x11 proxy/server
 */

#ifdef X11OPT

#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <time.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include "seccomp_helper.h"
#include "../misc.h"
#include "../eslib/eslib.h"
#define X11META_MAXARGS 10

int syscalls[MAX_SYSCALLS];
unsigned int g_x11meta_width;
unsigned int g_x11meta_height;
char g_x11meta_sockname[MAX_SYSTEMPATH];

extern gid_t g_rgid;
extern char g_newroot[MAX_SYSTEMPATH];
extern char *gethome();
extern int jail_process(char *chroot_path,
		 uid_t set_reuid,
		 gid_t set_regid,
		 int  *whitelist,
		 unsigned long seccomp_opts,
		 int *cap_e,
		 int *cap_p,
		 int *cap_i,
		 int can_write,
		 int can_exec);
/*
 *  XXX this should probably just use a config file
 *  for sanity sake when something breaks/changes
 */
static int x11meta_setup_seccomp()
{
	unsigned int i;
	/* set up new seccomp filter */
	for (i = 0; i < sizeof(syscalls) / sizeof(syscalls[0]); ++i)
	{
		syscalls[i] = -1;
	}
	i = 0;
	syscalls[i]   = syscall_getnum("__NR_recv");
	syscalls[++i] = syscall_getnum("__NR_poll");
	syscalls[++i] = syscall_getnum("__NR_writev");
	syscalls[++i] = syscall_getnum("__NR_clock_gettime");
	syscalls[++i] = syscall_getnum("__NR_read");
	syscalls[++i] = syscall_getnum("__NR_setitimer");
	syscalls[++i] = syscall_getnum("__NR_select");
	syscalls[++i] = syscall_getnum("__NR_sigreturn");
	syscalls[++i] = syscall_getnum("__NR_mmap2");
	syscalls[++i] = syscall_getnum("__NR_close");
	syscalls[++i] = syscall_getnum("__NR_open");
	syscalls[++i] = syscall_getnum("__NR_fstat64");
	syscalls[++i] = syscall_getnum("__NR_brk");
	syscalls[++i] = syscall_getnum("__NR_munmap");
	syscalls[++i] = syscall_getnum("__NR_fcntl64");
	syscalls[++i] = syscall_getnum("__NR_rt_sigprocmask");
	syscalls[++i] = syscall_getnum("__NR_write");
	syscalls[++i] = syscall_getnum("__NR__llseek");
	syscalls[++i] = syscall_getnum("__NR_rt_sigaction");
	syscalls[++i] = syscall_getnum("__NR_accept");
	syscalls[++i] = syscall_getnum("__NR_getsockopt");
	syscalls[++i] = syscall_getnum("__NR_shutdown");
	syscalls[++i] = syscall_getnum("__NR_mprotect");
	syscalls[++i] = syscall_getnum("__NR_access");
	syscalls[++i] = syscall_getnum("__NR_stat64");
	syscalls[++i] = syscall_getnum("__NR_uname");
	syscalls[++i] = syscall_getnum("__NR_recvmsg");
	syscalls[++i] = syscall_getnum("__NR_socket");
	syscalls[++i] = syscall_getnum("__NR_getrlimit");
	syscalls[++i] = syscall_getnum("__NR_setsockopt");
	syscalls[++i] = syscall_getnum("__NR_unlink");
	syscalls[++i] = syscall_getnum("__NR_getuid32");
	syscalls[++i] = syscall_getnum("__NR_getgid32");
	syscalls[++i] = syscall_getnum("__NR_geteuid32");
	syscalls[++i] = syscall_getnum("__NR_bind");
	syscalls[++i] = syscall_getnum("__NR_getegid32");
	syscalls[++i] = syscall_getnum("__NR_getsockname");
	syscalls[++i] = syscall_getnum("__NR_umask");
	syscalls[++i] = syscall_getnum("__NR_mremap");
	syscalls[++i] = syscall_getnum("__NR_listen");
	syscalls[++i] = syscall_getnum("__NR_sendto");
	syscalls[++i] = syscall_getnum("__NR_execve");
	syscalls[++i] = syscall_getnum("__NR_time");
	syscalls[++i] = syscall_getnum("__NR_futex");
	syscalls[++i] = syscall_getnum("__NR_set_thread_area");
	syscalls[++i] = syscall_getnum("__NR_getppid");
	syscalls[++i] = syscall_getnum("__NR_getpgrp");
	syscalls[++i] = syscall_getnum("__NR_set_robust_list");
	syscalls[++i] = syscall_getnum("__NR_connect");
	syscalls[++i] = syscall_getnum("__NR_waitpid");
	syscalls[++i] = syscall_getnum("__NR_link");
	syscalls[++i] = syscall_getnum("__NR_chdir");
	syscalls[++i] = syscall_getnum("__NR_getpid");
	syscalls[++i] = syscall_getnum("__NR_pipe");
	syscalls[++i] = syscall_getnum("__NR_dup2");
	syscalls[++i] = syscall_getnum("__NR_gettimeofday");
	syscalls[++i] = syscall_getnum("__NR_fchmod");
	syscalls[++i] = syscall_getnum("__NR_clone");
	syscalls[++i] = syscall_getnum("__NR_lstat64");
	syscalls[++i] = syscall_getnum("__NR_setuid32");
	syscalls[++i] = syscall_getnum("__NR_setgid32");
	syscalls[++i] = syscall_getnum("__NR_set_tid_address");
	syscalls[++i] = syscall_getnum("__NR_clock_getres");
	syscalls[++i] = syscall_getnum("__NR_getpeername");
	syscalls[++i] = syscall_getnum("__NR_shmat");
	syscalls[++i] = syscall_getnum("__NR_shmdt");
	syscalls[++i] = syscall_getnum("__NR_shmget");
	syscalls[++i] = syscall_getnum("__NR_shmctl");
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
	if (len <= 0)
		goto disp_err;
	else if (len >= (int)sizeof(x11display_number) - 1)
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


#define CHECK_RETRY 1000 /* 10 seconds */
static int x11meta_check(pid_t p, char *oldsocket, char *metasocket, char *xauth)
{
	int status;
	unsigned int i = 0;
	pid_t r;

	/* give process some time to start up  */
	while(++i <= CHECK_RETRY)
	{
		usleep(10000);

		/* check errors */
		r = waitpid(p, &status, WNOHANG);
		if (r != 0) {
			if (r != p) {
				printf("waitpid: %s\n", strerror(errno));
				return -1;
			}
			if (WIFEXITED(status)) {
				printf("normal exit status: %d\n", status);
				return -1;
			}
			else {
				printf("abnormal exit status: %d\n", status);
				return -1;
			}
			return -1;
		}

		/* check for new socket */
		r = eslib_file_exists(metasocket);
		if (r == -1) {
			return -1;
		}
		else if (r == 0) {
			continue;
		}
		else {
			if (chown(oldsocket, 0,0))
				printf("chown oldsock: %s\n", strerror(errno));
			if (umount(oldsocket)) {
				printf("umount oldsock: %s\n", strerror(errno));
				return -1;
			}
			if (unlink(oldsocket)) {
				printf("unlink display: %s\n", strerror(errno));
				return -1;
			}
			if (umount(xauth)) {
				printf("umount xauth: %s\n", strerror(errno));
				return -1;
			}
			if (unlink(xauth)) {
				printf("unlink xauth: %s\n", strerror(errno));
				return -1;
			}
			return 0;
		}
	}
	printf("failed to start x11meta\n");
	return -1;
}

/* build a minimal environment to exec x11meta program in */
static int x11meta_buildfs(char *chroot_path, char *progpath, char *mainsocket)
{
	char *homepath;
	struct path_node node;

	homepath = gethome();
	if (homepath == NULL)
		return -1;

	memset(&node, 0, sizeof(node));

	/* rdonly */
	node.mntflags = MS_NOEXEC|MS_RDONLY|MS_NODEV|MS_UNBINDABLE|MS_NOSUID;
	snprintf(node.src,  MAX_SYSTEMPATH, "/usr/share");
	snprintf(node.dest, MAX_SYSTEMPATH, "%s/usr/share", chroot_path);
	eslib_file_mkdirpath(node.dest, 0775, 0);
	chmod(node.dest, 0775);
	if (pathnode_bind(&node))
		goto bind_err;
	snprintf(node.src,  MAX_SYSTEMPATH, "%s/.Xauthority", homepath);
	snprintf(node.dest, MAX_SYSTEMPATH, "%s/.Xauthority", chroot_path);
	eslib_file_mkfile(node.dest, 0775, 0);
	chmod(node.dest, 0775);
	if (pathnode_bind(&node))
		goto bind_err;
	snprintf(node.src,  MAX_SYSTEMPATH, "/etc/X11");
	snprintf(node.dest, MAX_SYSTEMPATH, "%s/etc/X11", chroot_path);
	eslib_file_mkdirpath(node.dest, 0775, 0);
	chmod(node.dest, 0775);
	if (pathnode_bind(&node))
		goto bind_err;

	/* +x */
	node.mntflags = MS_RDONLY|MS_NODEV|MS_UNBINDABLE|MS_NOSUID;
	snprintf(node.src,  MAX_SYSTEMPATH, "/usr/bin/xkbcomp");
	snprintf(node.dest, MAX_SYSTEMPATH, "%s/usr/bin/xkbcomp", chroot_path);
	eslib_file_mkfile(node.dest, 0775, 0);
	chmod(node.dest, 0775);
	if (pathnode_bind(&node))
		goto bind_err;
	snprintf(node.src,  MAX_SYSTEMPATH, "%s", progpath);
	snprintf(node.dest, MAX_SYSTEMPATH, "%s/%s", chroot_path, "x11meta");
	eslib_file_mkfile(node.dest, 0775, 0);
	chmod(node.dest, 0775);
	if (pathnode_bind(&node))
		goto bind_err;
	snprintf(node.src,  MAX_SYSTEMPATH, "/bin/sh");
	snprintf(node.dest, MAX_SYSTEMPATH, "%s/bin/sh", chroot_path);
	eslib_file_mkfile(node.dest, 0775, 0);
	chmod(node.dest, 0775);
	if (pathnode_bind(&node))
		goto bind_err;
	snprintf(node.src,  MAX_SYSTEMPATH, "/lib");
	snprintf(node.dest, MAX_SYSTEMPATH, "%s/lib", chroot_path);
	eslib_file_mkdirpath(node.dest, 0775, 0);
	chmod(node.dest, 0775);
	if (pathnode_bind(&node))
		goto bind_err;
	snprintf(node.src,  MAX_SYSTEMPATH, "/usr/lib");
	snprintf(node.dest, MAX_SYSTEMPATH, "%s/usr/lib", chroot_path);
	eslib_file_mkdirpath(node.dest, 0775, 0);
	chmod(node.dest, 0775);
	if (pathnode_bind(&node))
		goto bind_err;

	/* +w */
	snprintf(node.src, MAX_SYSTEMPATH, "%s", mainsocket);
	snprintf(node.dest, MAX_SYSTEMPATH, "%s%s", chroot_path, mainsocket);
	eslib_file_mkfile(node.dest, 0775, 0);
	chmod(node.dest, 0775);
	if (pathnode_bind(&node))
		goto bind_err;
	snprintf(node.dest, MAX_SYSTEMPATH, "%s/tmp/.X11-unix", chroot_path);
	if (chmod(node.dest, 01777))
		return -1;

	return 0;

bind_err:
	printf("bind %s ---> %s failed\n", node.src, node.dest);
	return -1;
}


static int jail_x11meta(char *chroot_path, char *progpath, char *mainsocket)
{
	/* newnet to prevent exposing other x11 servers */
	if (unshare(CLONE_NEWPID | CLONE_NEWNET)) {
		printf("unshare: %s\n", strerror(errno));
		return -1;
	}
	if (mkdir(chroot_path, 0775) && errno != EEXIST) {
		printf("minipod mkdir(%s): %s\n", chroot_path, strerror(errno));
		return -1;
	}
	if (chmod(chroot_path, 0770)) {
		printf("chroot: %s\n", strerror(errno));
		return -1;
	}
	if (x11meta_buildfs(chroot_path, progpath, mainsocket)) {
		return -1;
	}
	if (x11meta_setup_seccomp()) {
		return -1;
	}
	if (jail_process(chroot_path, 0, 0, syscalls, 0, NULL, NULL, NULL, 0, 0)) {
		printf("jail_process failed\n");
		return -1;
	}

	chmod("/tmp", 01777);
	return 0;
}

static pid_t x11meta_exec(char *progpath, char *chroot_path,
                          char *argv[],   char *mainsocket)
{
	pid_t p;
	p = fork();
	if (p == -1) {
		printf("fork(): %s\n", strerror(errno));
		return -1;
	}
	else if (p == 0) {
		int exempt[] = { STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO };

		if (eslib_proc_setenv("XAUTHORITY", "/.Xauthority"))
			_exit(-1);
		if (close_descriptors(exempt, 3))
			_exit(-1);
		if (jail_x11meta(chroot_path, progpath, mainsocket))
			_exit(-1);
		if (execve("/x11meta", argv, environ))
			printf("execve: %s\n", strerror(errno));

		_exit(-1);
	}
	return p;
}

int x11meta_setup(char *x11meta)
{
	char mainsocket[MAX_SYSTEMPATH];
	char metasocket[MAX_SYSTEMPATH];
	char progpath[MAX_SYSTEMPATH];
	char chroot_path[MAX_SYSTEMPATH];
	char metadisplay[32];
	char resolution[32];
	char rhex[128];
	char randnum[10];
	char *argv[X11META_MAXARGS];
	char procname[] = "x11meta";
	char opt_screen[] = "-screen";
	struct timespec t;
	char *display;
	char *displaynum;
	unsigned int i  = 0;
	unsigned int n  = 0;
	unsigned int rc = 0;
	unsigned int dlen;
	pid_t p, c;

	if (g_x11meta_width == 0 || g_x11meta_height == 0
			|| g_x11meta_height > 32000 || g_x11meta_height > 32000)
		return -1;

	memset(&t, 0, sizeof(t));
	memset(randnum, 0, sizeof(randnum));
	memset(mainsocket, 0, sizeof(mainsocket));
	memset(metasocket, 0, sizeof(metasocket));
	memset(resolution, 0, sizeof(resolution));
	memset(metadisplay, 0, sizeof(metadisplay));
	memset(chroot_path, 0, sizeof(chroot_path));
	memset(g_x11meta_sockname, 0, sizeof(g_x11meta_sockname));
	snprintf(chroot_path, sizeof(chroot_path), "%s/.x11meta", POD_PATH);

	/* process name */
	argv[i] = procname;
	if (++i >= X11META_MAXARGS)
		return -1;

	/* program path */
	memset(progpath, 0, sizeof(progpath));
	progpath[MAX_SYSTEMPATH-1] = '\0';
	if (strncmp(x11meta, "xnest", 6) == 0) {
		strncpy(progpath, X11META_XNEST, MAX_SYSTEMPATH-1);
	}
	else if (strncmp(x11meta, "xephyr", 7) == 0) {
		strncpy(progpath, X11META_XEPHYR, MAX_SYSTEMPATH-1);
	}
	else {
		printf("invalid x11meta option\n");
		return -1;
	}

	/* setup new socket and display */
	display = eslib_proc_getenv("DISPLAY");
	if (display == NULL) {
		printf("missing X11 $DISPLAY environment variable\n");
		return -1;
	}

	displaynum = x11get_displaynum(display, &dlen);
	if (displaynum == NULL) {
		return -1;
	}
	/* generate new number for meta display to avoid lock file collision */
	clock_gettime(CLOCK_MONOTONIC_RAW, &t);
	if (randhex(rhex, sizeof(rhex), t.tv_nsec + getpid() + t.tv_sec,
				1000 + ((t.tv_nsec+t.tv_sec)%400))) {
		return -1;
	}
	rc = 0;
	for (n = 0; n < sizeof(randnum)-1; ++n)
	{
		for (; rc < sizeof(rhex); ++rc)
		{
			if (rhex[rc] >= '0' && rhex[rc] <= '9') {
				randnum[n] = rhex[rc];
				++rc;
				break;
			}
		}
		if (rc >= sizeof(rhex))
			break;
	}
	randnum[sizeof(randnum)-1] = '\0';
	snprintf(mainsocket, sizeof(mainsocket),
			"/tmp/.X11-unix/X%s", displaynum);
	snprintf(metasocket, sizeof(metasocket),
			"%s/tmp/.X11-unix/X%s",chroot_path, randnum);
	snprintf(metadisplay, sizeof(metadisplay), ":%s.0", randnum);

	argv[i] = metadisplay;
	if (++i >= X11META_MAXARGS)
		return -1;

	/* meta display resolution */
	argv[i] = opt_screen;
	if (++i >= X11META_MAXARGS)
		return -1;
	snprintf(resolution,sizeof(resolution),
			"%dx%d", g_x11meta_width, g_x11meta_height);
	argv[i] = resolution;
	if (++i >= X11META_MAXARGS)
		return -1;

	c = fork();
	if (c == -1) {
		return -1;
	}
	if (c == 0) {
		char umountsock[MAX_SYSTEMPATH];
		char localxauth[MAX_SYSTEMPATH];
		memset(umountsock, 0, sizeof(umountsock));
		memset(localxauth, 0, sizeof(localxauth));
		/* exec and check need to be in same new mount namespace */
		if (unshare(CLONE_NEWNS)) {
			printf("unshare: %s\n", strerror(errno));
			_exit(-1);
		}

		p = x11meta_exec(progpath, chroot_path, argv, mainsocket);
		if (p == -1) {
			printf("exec_x11meta failed\n");
			_exit(-1);
		}
		snprintf(umountsock, sizeof(umountsock), "%s%s",chroot_path,mainsocket);
		snprintf(localxauth, sizeof(localxauth), "%s/.Xauthority",chroot_path);
		if (x11meta_check(p, umountsock, metasocket, localxauth)) {
			_exit(-1);
		}
		_exit(0);
	}

	while (1)
	{
		int r;
		int status;
		r = waitpid(c, &status, 0);
		if (r == -1 && errno != EINTR) {
			printf("waitpid: %s\n", strerror(errno));
			return -1;
		}
		if (r == c && WIFEXITED(status) && WEXITSTATUS(status) == 0) {
			break;
		}
		else {
			printf("x11meta_check failed: %d\n", status);
			return -1;
		}

	}

	/* pick this up later in pod.c x11meta_hookup */
	if (eslib_proc_setenv("DISPLAY", metadisplay)) {
		return -1;
	}
	snprintf(g_x11meta_sockname, sizeof(g_x11meta_sockname),"X%s", randnum);
	return 0;
}


#endif
