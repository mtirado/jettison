/* (c) 2015 Michael R. Tirado -- GPLv3, GNU General Public License, version 3.
 * contact: mtirado418@gmail.com
 *
 * jettison.c
 * wrapper for whitelist pod configuration file.
 *
 * read pod configuration file.
 * clone
 * setup pod environment
 * drop privs
 * exec.
 *
 */

#define _GNU_SOURCE
#include <sched.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <linux/audit.h>
#include <linux/seccomp.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <termios.h>
#include <time.h>
#include "pod.h"
#include "misc.h"
#include "util/seccomp_helper.h"
#include "eslib/eslib.h"

#define MAX_ARGV_LEN 1024 * 16 /* 16KB */
#define IOBUFLEN 4096 * 8 /* 32KB */

#define MAX_PROCNAME 17
#define MAX_OPTLEN 32
/* highest stack value system allows */
#ifndef MAX_SYSTEMSTACK
	#define MAX_SYSTEMSTACK  (1024 * 1024 * 16) /* 16MB */
#endif

#ifndef INIT_PATH
	#define INIT_PATH="/usr/local/bin/jettison_init"
#endif
#ifndef PRELOAD_PATH
	#define PRELOAD_PATH="/usr/local/bin/jettison_preload.so"
#endif

#ifdef __x86_64__ /* TODO this is untested... add other arch's */
	#define SYSCALL_ARCH AUDIT_ARCH_X86_64
#elif __i386__
	#define SYSCALL_ARCH AUDIT_ARCH_I386
#else
	#error arch lacks systemcall define, add it and test!
#endif

extern char **environ;
extern int tracecalls(pid_t p, int ipc);

/* pod.c globals */
extern char g_fcaps[64];
extern int  g_syscalls[MAX_SYSCALLS];
extern unsigned int g_syscall_idx;

/* entry and  filter function type */
typedef int (*main_entry)(void *);
typedef int (*filter_func)(void *);

/* input to clone func */
unsigned int g_podflags;
main_entry g_entry;
/* TODO, for C api users to close fd's after clone
 * or just make strong note that they should do this
 * immediately in main_entry, also be aware there is
 * a memory leak that should be handled, see pod_free().
 * this has no effect on standalone jettison.
 */
filter_func g_filter;
void *g_filterdata;

char *g_progpath;
char g_procname[MAX_PROCNAME];
int  g_newpid; /* process to wait for */

int g_daemon;
int g_logoutput;
int g_stdout_logfd;
int g_daemon_pipe[2];

/* seccomp */
long g_retaction;
int  g_strict;
int  g_blocknew;
int  g_allow_ptrace;

/* pod tty i/o */
int g_pty_notify[2];
int g_ptym;

/* for stopping/resuming jettison_init before exec */
int g_traceipc[2];
int g_tracecalls;

/* users real uid/gid */
uid_t g_ruid;
gid_t g_rgid;


char g_newroot[MAX_SYSTEMPATH];
char g_pty_slavepath[MAX_SYSTEMPATH];
char g_nullspace[MAX_SYSTEMPATH];
char g_executable_path[MAX_SYSTEMPATH];
char g_podconfig_path[MAX_SYSTEMPATH];
char g_cwd[MAX_SYSTEMPATH]; /* directory jettison was called from */
size_t g_stacksize;


/* must be called first to obtain podflags and chroot path. */
int jettison_readconfig(char *cfg_path, unsigned int *outflags)
{
	return pod_prepare(cfg_path, g_newroot, outflags);
}


/* only valid if jettison_podconfigure has returned 0 ! */
char *jettison_get_newroot()
{
	return g_newroot;
}

static int create_nullspace()
{
	memset(g_nullspace, 0, sizeof(g_nullspace));
	snprintf(g_nullspace, sizeof(g_nullspace), "%s/.nullspace", POD_PATH);
	if (eslib_file_exists(POD_PATH) != 1) {
		printf("directory missing: %s\n", POD_PATH);
		return -1;
	}
	if (eslib_file_path_check(g_nullspace))
		return -1;

	/* directory may have not been created yet */
	if (eslib_file_mkdirpath(g_nullspace, 0755, 0) != 0) {
		printf("could not create: %s\n", g_nullspace);
		return -1;
	}
	chmod(g_nullspace, 0755);
	return 0;
}

/* uses /opt/pods/.nullspace as chroot directory */
static int downgrade_relay()
{
	unsigned int i;
	unsigned long remountflags =	  MS_REMOUNT
					| MS_NOSUID
					| MS_NOEXEC
					| MS_NODEV
					| MS_RDONLY;
	if (unshare(CLONE_NEWNS | CLONE_NEWPID)) {
		printf("relay unshare: %s\n", strerror(errno));
		return -1;
	}
	if (mount(g_nullspace, g_nullspace, "bind",
				MS_BIND, NULL)) {
		printf("could not bind mount: %s\n", strerror(errno));
		return -1;
	}
	if (mount(g_nullspace, g_nullspace, "bind",
				MS_BIND|remountflags, NULL)) {
		printf("could not bind mount: %s\n", strerror(errno));
		return -1;
	}
	if (mount(NULL, g_nullspace, NULL, MS_SLAVE|MS_REC, NULL)) {
		printf("could not make slave: %s\n", strerror(errno));
		return -1;
	}
	if (chdir(g_nullspace) < 0) {
		printf("chdir(\"%s\") failed: %s\n", g_nullspace, strerror(errno));
		return -1;
	}
	/* remount subtree to / */
	if (mount(g_nullspace, "/", NULL, MS_MOVE, NULL) < 0) {
		printf("mount / MS_MOVE failed: %s\n", strerror(errno));
		return -1;
	}
	if (chroot(g_nullspace) < 0) {
		printf("chroot failed: %s\n", strerror(errno));
		return -1;
	}
	/*chroot doesnt change CWD, so we must.*/
	if (chdir("/") < 0) {
		printf("chdir(\"/\") failed: %s\n", strerror(errno));
		return -1;
	}
	/* apply seccomp filter */
	for (i = 0; i < sizeof(g_syscalls) / sizeof(g_syscalls[0]); ++i)
	{
		g_syscalls[i] = -1;
	}
	i = 0;

	/*g_syscalls[i] = syscall_getnum("__NR_select");*/
	g_syscalls[i]   = syscall_getnum("__NR__newselect");
	g_syscalls[++i] = syscall_getnum("__NR_close");
	g_syscalls[++i] = syscall_getnum("__NR_waitpid");
	g_syscalls[++i] = syscall_getnum("__NR_write");
	g_syscalls[++i] = syscall_getnum("__NR_read");
	g_syscalls[++i] = syscall_getnum("__NR_capset");
	g_syscalls[++i] = syscall_getnum("__NR_gettid");
	g_syscalls[++i] = syscall_getnum("__NR_exit");
	g_syscalls[++i] = syscall_getnum("__NR_exit_group");
	g_syscalls[++i] = syscall_getnum("__NR_ioctl");
	g_syscalls[++i] = syscall_getnum("__NR_sigreturn");
	g_syscalls[++i] = syscall_getnum("__NR_nanosleep"); /* on log write blocked */
	if (filter_syscalls(SYSCALL_ARCH, g_syscalls,
				 count_syscalls(g_syscalls,MAX_SYSCALLS),
				 0, SECCOMP_RET_ERRNO)) {
		printf("unable to apply seccomp filter\n");
		return -1;
	}

	if (clear_caps()) {
		printf("\rclear_caps failed\r\n");
		return -1;
	}

	return 0;
}

/* we need to adjust some paths in environment, i have a feeling this
 * is going to need to be a config option...
 * or maybe Xorg is the only culprit?
 * it may be a better idea to just filter whole environment for /home/username
 * and replace it with /podhome
 *
 * TODO: option to whitelist additional preloads
 * 	 also, do the above mentioned for all home paths, we need more flexible
 * 	 env filtering in general, whitelist env option in config file?
 */
#define ENV_MAX_ITER 9001
static int change_environ()
{

	if (eslib_proc_getenv("HOME")) {
		if (eslib_proc_setenv("HOME", "/podhome")) {
			printf("error setting $HOME\n");
			return -1;
		}
	}
	else {
		printf("$HOME is not set\n");
		return -1;
	}

	if (eslib_proc_getenv("XAUTHORITY")) {
		if (eslib_proc_setenv("XAUTHORITY", "/podhome/.Xauthority")) {
			printf("error setting $XAUTHORITY\n");
			return -1;
		}
	}
	if (g_daemon && g_logoutput) {
		if (eslib_proc_setenv("LD_PRELOAD", PRELOAD_PATH)) {
			printf("error setting LD_PRELOAD\n");
			return -1;
		}
	}
	return 0;
}

/* called from within new thread */
int jettison_initiate(unsigned int podflags)
{
	int retval;
	int noproc = (podflags & (1 << OPTION_NOPROC));
	struct stat st;


	/* filter callback, for closing fd's and whatnot */
	if (g_filter && g_filter(g_filterdata)) {
		printf("clone filter failed\n");
		return -1;
	}

	/* enter pod environment */
	if ((retval = pod_enter()) < 0) {
		printf("pod_enter failure: %d\n", retval);
		return -2;
	}


	memset(&st, 0, sizeof(st));
	retval = stat("/proc", &st);
	if (noproc && retval != -1 && S_ISDIR(st.st_mode)) {
		if (umount("/proc")) {
			printf("could not unmount /proc\n");
			return -3;
		}
	}
	else if (retval == -1) {
		printf("/proc is missing, or is not a directory.\n");
	}


	return 0;
}

/* new thread function */
int jettison_clone_func(void *data)
{

	close(g_ptym);
	close(g_pty_notify[0]);
	close(g_traceipc[0]);
	close(g_daemon_pipe[0]);

	if (setsid() == -1) {
		printf("setsid(): %s\n", strerror(errno));
		return -1;
	}

	/* switch terminals and tell io relay to begin */
	if (!g_daemon) {
		if (setuid(g_ruid)) {
			printf("setuid fail\n");
			return -1;
		}
		if (switch_terminal(g_pty_slavepath, 0)) {
			printf("switch_terminal()\n");
			return -1;
		}
		/* tell io relay that our new terminal is open */
		if (write(g_pty_notify[1], "K", 1) != 1) {
			printf("write: %s\n", strerror(errno));
			return -1;
		}
		/* all files except podhome are root owned */
		if (setuid(0)) {
			printf("clone uid error\n");
			return -1;
		}
	}
	close(g_pty_notify[1]);
	/* enter pod environment */
	if (jettison_initiate(g_podflags) < 0) {
		return -1;
	}

	change_environ();
	/* either call func, or exec */
	if (g_entry) {
		return -1; /* TODO g_entry(data);*/
	}
	else {
		/*char *benv[6] = {
			"PATH=/sbin:/usr/sbin:/bin:/usr/bin:/usr/local/bin",
			"HOME=/podhome",
			"SHELL=/bin/bash",
			"TERM=linux",
			"DISPLAY=:0.0",
			NULL
		};*/

		if (chown("/podhome", g_ruid, g_rgid)) {
			printf("chown /podhome failed\n");
			return -1;
		}

		/* switch back to real user credentials */
		if (setregid(g_rgid, g_rgid)) {
			printf("error setting gid(%d): %s\n",
					g_rgid, strerror(errno));
			return -1;
		}
	        if (setreuid(g_ruid, g_ruid)) {
			printf("error setting uid(%d): %s\n",
					g_ruid, strerror(errno));
			return -1;
		}

		if (chmod("/podhome", 0750)) {
			printf("home directory error\n");
			return -1;
		}
		chdir("/podhome");

		/* install seccomp filter. block ptrace if no options specified */
		if (g_syscall_idx == 0 && !g_blocknew && g_allow_ptrace) {
			printf("**calling exec without seccomp filter**\n");
		}
		else {
			unsigned int opts = 0;
			if (g_tracecalls)
				opts |= SECCOPT_TRACING;
			if (g_blocknew)
				opts |= SECCOPT_BLOCKNEW;
			if (g_allow_ptrace)
				opts |= SECCOPT_PTRACE;
			if (filter_syscalls(SYSCALL_ARCH, g_syscalls,
					 count_syscalls(g_syscalls, MAX_SYSCALLS),
					 opts, g_retaction)) {
				printf("unable to apply seccomp filter\n");
				return -1;
			}
		}

		if (execve(INIT_PATH, (char **)data, environ) < 0)
			printf("jettison_init exec error: %s\n", strerror(errno));
		return -1;
	}
}

/* clone the current process and return pid
 * returns -1 on error
 *
 * if we want to call exec set func to null, progpath will be the full
 * path to executable file, and data will be argv.
 * */
int jettison_clone(char *progpath, void *data, size_t stacksize,
		   main_entry entry, unsigned int podflags,
		    filter_func clone_filter, void *filter_data)
{
	unsigned int cloneflags;
	char *newstack;
	void *topstack;
	pid_t p;


	if (stacksize >= MAX_SYSTEMSTACK) {
		printf("maximum possible stacksize: %d\n", MAX_SYSTEMSTACK);
		return -1;
	}
	newstack = malloc(stacksize);
	if (newstack == NULL) {
		printf("malloc error\n");
		return -1;
	}
	topstack = newstack + stacksize;

	/* new mount namespaces for every pod */
	cloneflags = CLONE_NEWNS | CLONE_NEWPID;
	if (podflags & (1 << OPTION_ROOTPID))
		cloneflags &= ~CLONE_NEWPID;

	/* TODO actually test newnet.. isolates abstract socket namespace */
	if (podflags & (1 << OPTION_NEWNET))
		cloneflags |= CLONE_NEWNET;

	/* setup some extra parameters and create new thread */
	g_progpath = progpath;
	g_podflags = podflags;
	g_entry = entry;
	g_filter = clone_filter;
	g_filterdata = filter_data;
	p = clone(jettison_clone_func, topstack,
			cloneflags | SIGCHLD, data);
	free(newstack);
	if (p == -1) {
		printf("clone: %s\n", strerror(errno));
		return -1;
	}
	return p;


}

/* jettison a program */
int jettison_program(char *path, char *args[], size_t stacksize,
		     unsigned int podflags, main_entry clone_filter,
		     void *filter_data)
{
	if (path == NULL || path[0] != '/') {
		printf("invalid path\n");
		return -1;
	}

	return jettison_clone(path, (void *)args, stacksize, NULL,
			podflags, clone_filter, filter_data);
}


/*
 * checks program arguments and reorder additional arguments into
 * threads argv array to be passed directly to execve call
 */
int process_arguments(int argc, char *argv[])
{
	unsigned int len;
	int i;
	int argidx = 3;
	int argnew;
	char *err;

	/* must have executable path, and pod config file present */
	if (argc < 3)
		goto err_usage;

	g_stacksize = 0;
	g_retaction = SECCOMP_RET_KILL;
	g_tracecalls = 0;
	g_blocknew = 0;
	g_allow_ptrace = 0;
	g_strict = 0;

	for (i = 1; i < argc; ++i)
	{
		switch(i)
		{

		/* read mandatory arguments */
		case 1:
		case 2:
			len = strnlen(argv[i], MAX_SYSTEMPATH);
			if (len < 2) { /* path must have a char + null term */
				printf("invalid executable path\n");
				return -1;
			}
			else if (len >= MAX_SYSTEMPATH) {
				printf("executable path too long\n");
				return -1;
			}
			if (i == 1)
				strncpy(g_executable_path, argv[i], len);
			else if (i == 2)
				strncpy(g_podconfig_path, argv[i], len);

			break;

		/* check additional options */
		default:
			len = strnlen(argv[i], MAX_OPTLEN);
			if (len >= MAX_OPTLEN || len == 0)
				goto err_usage;

			if (strncmp(argv[i], "--stacksize", len) == 0) {
				if (argc < i+1 || argv[i+1] == '\0')
					goto missing_opt;
				errno = 0;
				++i;
				g_stacksize = strtol(argv[i], &err, 10);
				if (*err || errno)
					goto bad_opt;
				g_stacksize *= 1024; /* kilobytes to bytes */
				if (g_stacksize >= MAX_SYSTEMSTACK)
					goto bad_opt;
				argidx += 2;
			}
			else if (strncmp(argv[i], "--procname", len) == 0) {
				if (argc < i+1 || argv[i+1] == '\0')
					goto missing_opt;
				++i;
				len = strnlen(argv[i], MAX_PROCNAME);
				if (len >= MAX_PROCNAME) {
					printf("max procname: %d\n", MAX_PROCNAME-1);
					goto bad_opt;
				}
				strncpy(g_procname, argv[i], MAX_PROCNAME-1);
				g_procname[MAX_PROCNAME-1] = '\0';
				argv[0] = g_procname;
				argidx += 2;
			}
			else if (strncmp(argv[i], "--strict", len) == 0) {
				g_strict = 1;
				argidx  += 1;
			}
			else if (strncmp(argv[i], "--tracecalls", len) == 0) {
				g_tracecalls = 1;
				argidx  += 1;
			}
			else if (strncmp(argv[i], "--block-new-filters", len) == 0) {
				g_blocknew = 1;
				argidx  += 1;
			}
			else if (strncmp(argv[i], "--allow-ptrace", len) == 0) {
				g_allow_ptrace = 1;
				argidx  += 1;
			}
			else if (strncmp(argv[i], "--daemon", len) == 0) {
				g_daemon = 1;
				argidx  += 1;
			}
			else if (strncmp(argv[i], "--logoutput", len) == 0) {
				g_logoutput = 1;
				argidx  += 1;
			}
			else {
				/* program arguments begin here, break loop */
				i = argc;
			}
			break;
		}

	}
	/* shifted arguments start here */
	argnew = argidx;

	/* launch through jettison_init which needs path in argv[1] */
	if (g_tracecalls) {
		g_blocknew = 1;
	}
	argidx = 2;

	/* shift remaining args for new exec call*/
	i = argnew;
	while(i < argc)
	{
		argv[argidx++] = argv[i++];
	}


	if (g_tracecalls)
		g_retaction = SECCOMP_RET_TRAP;
	else if (g_strict)
		g_retaction = SECCOMP_RET_KILL;
	else
		g_retaction = SECCOMP_RET_ERRNO;

	/* terminate arguments */
	argv[argidx] = NULL;
	return 0;

missing_opt:
	printf("%s, ", argv[i]);
	printf("missing option parameter\n");
	return -1;

bad_opt:
	printf("%s, ", argv[i]);
	printf("invalid option parameter\n");
	return -1;

err_usage:
	printf("\n");
	printf("usage:\n");
	printf("jettison <executable> <podconfig> <options> <arg1, arg2, ..argn>\n");
	printf("\n");
	printf("additional options:\n");
	printf("\n");
	printf("--procname <process name>\n");
	printf("        set new process name\n");
	printf("\n");
	printf("--stacksize  <kilobytes>\n");
	printf("        set new process stack size\n");
	printf("\n");
	printf("--strict\n");
	printf("        seccomp fail kills process instead of ENOSYS error\n");
	printf("\n");
	printf("--tracecalls\n");
	printf("        print all known system calls made. creates a template\n");
	printf("        configuration file in cwd with optimized whitelist\n");
	printf("\n");
	printf("--block-new-filters\n");
	printf("        prevent additional filters from being installed\n");
	printf("        this will improve performance with programs that set\n");
	printf("        their own seccomp filters.   --tracecalls always\n");
	printf("        sets this for correct blocked call reporting. \n");
	printf("\n");
	printf("--allow-ptrace\n");
	printf("        whitelist ptrace (it's always blacklisted otherwise)\n");
	printf("        see seccomp documentation, there are security concerns\n");
	printf("\n");
	printf("\n");
	return -1;
}



/*
 * if we get a signal that would terminate program, we need to
 * reset the terminal back to it's original settings before exit
 */
struct termios g_origterm;
void exit_func()
{
	tcsetattr(STDIN_FILENO, TCSANOW, &g_origterm);
	tcflush(STDIN_FILENO, TCIOFLUSH);
}

/* terminal resize message */
static int handle_sigwinch()
{
	struct winsize w;

	memset(&w, 0, sizeof(w));
	/* get our main tty size */
	if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &w) == -1)
		return -1;
	/*set pty size */
	if (ioctl(g_ptym, TIOCSWINSZ, &w) == -1)
		return -1;

	return 0;
}

static void relayio_sighand(int signum)
{
	if (signum == SIGWINCH) {
		if (handle_sigwinch())
			printf("sigwinch handler: %s\n", strerror(errno));
		return;
	}
	printf("jettison received signal: %d\n", signum);
	exit_func();
	exit(-1);
}

/* catch everything short of a sigkill */
static void relayio_sigsetup()
{
	signal(SIGTERM,   relayio_sighand);
	signal(SIGINT,    relayio_sighand);
	signal(SIGHUP,    relayio_sighand);
	signal(SIGQUIT,   relayio_sighand);
	signal(SIGILL,    relayio_sighand);
	signal(SIGABRT,   relayio_sighand);
	signal(SIGFPE,    relayio_sighand);
	signal(SIGSEGV,   relayio_sighand);
	signal(SIGPIPE,   relayio_sighand);
	signal(SIGALRM,   relayio_sighand);
	signal(SIGUSR1,   relayio_sighand);
	signal(SIGUSR2,   relayio_sighand);
	signal(SIGBUS,    relayio_sighand);
	signal(SIGPOLL,   relayio_sighand);
	signal(SIGIO,     relayio_sighand);
	signal(SIGPROF,   relayio_sighand);
	signal(SIGSYS,    relayio_sighand);
	signal(SIGVTALRM, relayio_sighand);
	signal(SIGXCPU,   relayio_sighand);
	signal(SIGXFSZ,   relayio_sighand);
	signal(SIGIOT,    relayio_sighand);
	signal(SIGSTKFLT, relayio_sighand);
	signal(SIGUNUSED, relayio_sighand);
	signal(SIGTRAP,   relayio_sighand);

	if (!g_daemon) {
		signal(SIGWINCH, relayio_sighand);
	}
}



/*
 * write [size] bytes from buf to fd
 * returns
 *  n bytes written
 * -1 on error
 *
 *  note: this functions blocks until all data is is pushed out of buffer
 */
static int pushbuf(int fd, char *buf, unsigned int size)
{
	int r;
	unsigned int count = 0;

	while (1)
	{
		r = write(fd, &buf[count], size - count);
		if (r > 0) {
			count += r;
			if (count == size)
				break;
		}
		else if (r < 0 && (errno == EINTR || errno == EAGAIN)) {
			usleep(500);
		}
		else if (r == 0)
			usleep(500);
		else {
			printf("pushbuf write: %s\n", strerror(errno));
			return -1;
		}
	}
	return count;
}

/*
 * read up to [size] bytes from fd to buf
 * returns
 *  n bytes read
 *  0 nothing to read
 * -1 on error
 *
 *  note: this function does not block unless EINTR
 */
static int fillbuf(int fd, char *buf, unsigned int size)
{
	int r;

	while (1)
	{
		r = read(fd, buf, size);
		if (r > 0)
			return r;
		else if (r == 0)
			break;
		else if (r < 0 && errno == EAGAIN)
			break;
		else if (r < 0 && errno == EINTR)
			continue;
		else {
			return -1;
		}
	}
	return 0;
}

/* infinite loop on blocked writes */
static int logwrite(int fd, char *buf, int bytes)
{
	while(bytes > 0)
	{
		/* TODO catch all terminating signals and kill daemon */
		int r = write(fd, buf, bytes);
		if (r == bytes) {
			break;
		}
		else if (r == -1) {
			if (errno == EINTR) {
				continue;
			}
			else if (errno == EDQUOT || errno == ENOSPC) {
				/* TODO syslog + to console  */
				printf("logwrite:%s", strerror(errno));
				usleep(10000000); /* 10+ second sleep */
			}
			else {
				printf("logwrite: ");
				printf("%s\n", strerror(errno));
				return -1;
			}
		}
		else if (r > 0 && r < bytes) {
			bytes -= r;
			buf += r;
		}
		else {
			printf("unexpected error, r=%d\n", r);
			return -1;
		}
	}
	return 0;
}

/*
 * relay input from ours to theirs,
 * relay output from theirs to ours
 * loop until child proc exits, or error
 *
 * in loop, we check if there are bytes in buffer waiting to be written.
 * check write set, and write until buffer has been completely emptied.
 * if the buffer is empty, we check read set to read and refill.
 *
 */
static int relay_io(int stdout_logfd)
{
	char rbuf[IOBUFLEN]; /* buffer from them */
	char wbuf[IOBUFLEN]; /* buffer to them */
	unsigned int wpos;   /* current write position */
	unsigned int wbytes; /* number of bytes in read buffer */
	int r;
	int highfd;
	fd_set rds, wrs;
	struct timeval tmr;
	struct timeval instant;
	int ours, theirs;
	int loop = 1;
	int status;

	ours = STDIN_FILENO;
	theirs = g_ptym;

	if (ours == -1 || (!g_daemon && theirs  == -1))
		return -1;

	if (!g_daemon && (!isatty(ours) || !isatty(theirs))) {
		printf("relay_io not a tty\n");
		return -1;
	}

	memset(&instant, 0, sizeof(instant));
	memset(&tmr, 0, sizeof(tmr));
	tmr.tv_sec = 3;

	/* determine high fd number for select */
	highfd = (theirs > ours)  ? theirs : ours;
	++highfd;

	wpos = 0;
	wbytes = 0;
	memset(rbuf, 0, sizeof(rbuf));
	memset(wbuf, 0, sizeof(wbuf));


	if (g_daemon) {
		if (stdout_logfd == -1) {
			return 0;
		}
		if (dup2(stdout_logfd, STDOUT_FILENO) != STDOUT_FILENO
				|| dup2(stdout_logfd, STDERR_FILENO) != STDERR_FILENO) {
			printf("stdio dup error: %s\n", strerror(errno));
			return -1;
		}
		/* isolate this process + seccomp filter */
		if(downgrade_relay()) {
			printf("failed to downgrade relay\n");
			return -1;
		}
		/* daemon update loop */
		while (1)
		{
			tmr.tv_usec = 0;
			tmr.tv_sec = 5;
			FD_ZERO(&rds);
			FD_SET(g_daemon_pipe[0], &rds);

			r = select(g_daemon_pipe[0]+1, &rds, NULL, NULL, &tmr);
			if (stdout_logfd != -1 && FD_ISSET(g_daemon_pipe[0], &rds)) {
				r = read(g_daemon_pipe[0], rbuf, sizeof(rbuf)-1);
				if (r > 0) {
					if (logwrite(stdout_logfd, rbuf, r)) {
						return -1;
					}
				}
				else if (r == -1 && errno == EINTR) {
					;
				}
				else if (r == 0) {
					printf("daemon_pipe EOF\n");
					return -1;
				}
				else {
					printf("daemon_pipe error: %s\n", strerror(errno));
					return -1;
				}
			}
			if (waitpid(-1, &status, WNOHANG) == -1) {
				printf("daemon exited\n");
				close(stdout_logfd);
				return 0;
			}
		}
	}


	/* isolate this process + seccomp filter */
	if(downgrade_relay()) {
		printf("failed to downgrade relay\n");
		return -1;
	}

	handle_sigwinch(); /* set terminal size */
	/* wait for other process to switch terminal */
	while (read(g_pty_notify[0], rbuf, 1) == -1)
	{
		if (errno != EINTR) {
			printf("terminal notify error: %s\n", strerror(errno));
				return -1;
		}
	}
	close(g_pty_notify[0]);
	close(g_pty_notify[1]);
	/* normal pty io relay */
	while(loop)
	{
		tmr.tv_usec = 0;
		tmr.tv_sec = 5;

		/* wait for event */
		FD_ZERO(&rds);
		FD_ZERO(&wrs);
		FD_SET(ours, &rds);
		FD_SET(ours, &wrs);
		FD_SET(theirs, &wrs);
		FD_SET(theirs, &rds);

		if (waitpid(g_newpid, &status, WNOHANG) == g_newpid) {
			printf("process exiting\n");
			loop = 0;
			wbytes = 0;
		}
		/* waiting on them to consume wbuf */
		if (wbytes) {
			r = select(highfd, NULL, &wrs, NULL, &instant);
			if (r == -1 && errno != EINTR) {
				printf("writeset select(): %s\n", strerror(errno));
				goto fatal;
			}
			if (FD_ISSET(theirs, &wrs)) {
				r = pushbuf(theirs, &wbuf[wpos], wbytes - wpos);
				if (r == -1) {
					/*printf("pushbuf_theirs: %s\n", strerror(errno));*/
					goto fatal;
				}
				else {
					/* update pos */
					wpos += r;
					if (wpos == wbytes) {
						wpos = 0;
						wbytes = 0;
						continue;
					}
					else if (wpos > wbytes) {
						printf("relay io write error\n");
						return -1;
					}
				}
			}
		}
		else {
			/* check read set for input wait until data is ready. */
			r = select(highfd, &rds, NULL, NULL, &tmr);
			if (r == -1) {
				if (errno != EINTR) { /* we have a sighandler for this */
					printf("select(): %s\n", strerror(errno));
					goto fatal;
				}
			}
			/* read input from our side, and buffer it */
			if (FD_ISSET(ours, &rds)) {
				r = fillbuf(ours, wbuf, sizeof(wbuf)-1);
				if (r == -1) {
					printf("fillbuf_ours: %s\n", strerror(errno));
					goto fatal;
				}
				wbytes = r;
				wpos = 0;
			}

			/* read output from their side and print it */
			if (FD_ISSET(theirs, &rds)) {
				r = fillbuf(theirs, rbuf, sizeof(rbuf)-1);
				if (r == -1) {
					printf("fillbuf_theirs: %s\n", strerror(errno));
					goto fatal;
				}
				else if (r > 0) {
					if (pushbuf(STDOUT_FILENO, rbuf, r) == -1) {
						printf("pushbuf_stdout: %s\n", strerror(errno));
						goto fatal;
					}
					if (stdout_logfd != -1) {
						if (logwrite(stdout_logfd, rbuf, r)) {
							return -1;
						}
					}
				}
			}
		}
	}

fatal:
	return -1;
}

static int create_logfile()
{
	char logpath[MAX_SYSTEMPATH];
	char dst_str[16];
	char *fname;
	struct tm *t;
	time_t stamp;
	int year, mon, day, hour, min, sec, dlst;
	int fd;

	fname = eslib_file_getname(g_podconfig_path);
	if (fname == NULL) {
		return -1;
	}

	/* create timestamp */
	if (time(&stamp) == -1) {
		printf("time: %s\n", strerror(errno));
		return -1;
	}
	t = localtime(&stamp);
	if (t == NULL) {
		printf("localtime: %s\n", strerror(errno));
		return -1;
	}
	year = t->tm_year + 1900;
	mon  = t->tm_mon + 1;
	day  = t->tm_mday;
	hour = t->tm_hour;
	min  = t->tm_min;
	sec  = t->tm_sec;
	dlst = t->tm_isdst;
	if (dlst > 0)
		snprintf(dst_str, sizeof(dst_str), "[dst]");
	else if (dlst == 0)
		snprintf(dst_str, sizeof(dst_str), "[nodst]");
	else
		snprintf(dst_str, sizeof(dst_str), "[dsterr]");
	/* create file path */
	snprintf(logpath, sizeof(logpath), "./log.%s.%04d-%02d-%02dT%02d:%02d:%02d%s",
				fname, year, mon, day, hour, min, sec, dst_str);
	if (eslib_file_exists(logpath)) {
		printf("log file already exists?\n");
		return -1;
	}

	if (setuid(g_ruid)) {
		printf("setuid: %s\n", strerror(errno));
		return -1;
	}
	fd = open(logpath, O_WRONLY|O_CREAT|O_CLOEXEC, 0750);
	if (setuid(0)) {
		printf("setuid : %s\n", strerror(errno));
		return -1;
	}
	if (fd == -1) {
		printf("open: %s\n", strerror(errno));
		return -1;
	}
	if (chown(logpath, g_ruid, g_rgid)) {
		printf("chown: %s\n", strerror(errno));
		return -1;
	}
	return fd;
}


static int daemonize()
{
	int devnull;
	int outfile;
	pid_t p;
	devnull = open("/dev/null", O_RDWR|O_CLOEXEC);
	if (devnull == -1) {
		printf("could not open /dev/null\n");
		return -1;
	}

	/* pipe will be new stdout */
	outfile = g_daemon_pipe[1];
	if (outfile == -1) {
		outfile = devnull;
	}

	p = fork();
	if (p == -1) {
		printf("fork err: %s\n", strerror(errno));
		return -1;
	}
	else if (p) {
		_exit(0); /* exit main thread */
	}

	if (chdir("/") == -1) {
		printf("chdir(\"/\"): %s\n", strerror(errno));
		return -1;
	}
	if (setsid() == -1) {
		printf("setsid: %s\n", strerror(errno));
		return -1;
	}
	p = fork();
	if (p == -1) {
		printf("fork error: %s\n", strerror(errno));
		return -1;
	}
	else if (p) {
		printf("daemon forked: %d\n", p);
		_exit(0);
	}

	/* switch stdio fd's */
	if (dup2(devnull, STDIN_FILENO) != STDIN_FILENO
			|| dup2(outfile, STDOUT_FILENO) != STDOUT_FILENO
				|| dup2(outfile, STDERR_FILENO) != STDERR_FILENO) {
		printf("stdio dup error: %s\n", strerror(errno));
		return -1;
	}

	return 0;
}

static int do_trace(pid_t tracee)
{
	if (g_daemon) {
		/* create template file at cwd */
		if (chdir(g_cwd)) {
			printf("daemon trace chdir: %s\n", strerror(errno));
			return -1;
		}
	}
	if (tracecalls(tracee, g_traceipc[0])) {
		printf("tracecalls error: %d\n", tracee);
		_exit(-1);
	}
	printf("error\n");
	_exit(-1);
}

/* tracer should be parent of cloned thread
 * (for yama mode 1 TODO test it!)
 */
static int trace_fork(char **argv)
{
	pid_t p;
	p = fork();
	if (p == -1) {
		return -1;
	}
	else if (p == 0) {
		char buf[64];

		/* TODO -- install seccomp on tracer thread */
		setuid(g_ruid);
		if (socketpair(AF_UNIX, SOCK_STREAM, 0, g_traceipc)) {
			printf("socketpair: %s\n", strerror(errno));
			return -1;
		}
		setuid(0);

		snprintf(buf, sizeof(buf), "%d", g_traceipc[1]);
		if (eslib_proc_setenv("JETTISON_TRACEFD", buf)) {
			printf("setenv error\n");
			return -1;
		}

		p = jettison_program(g_executable_path, argv, g_stacksize,
					    g_podflags, NULL, NULL);

		close(g_traceipc[1]);
		close(g_daemon_pipe[0]);
		close(g_daemon_pipe[1]);
		close(g_pty_notify[0]);
		close(g_pty_notify[1]);
		close(g_ptym);
		/* drop tracer privs */
		if (setregid(g_rgid, g_rgid)) {
			printf("error setting gid(%d): %s\n",
					g_rgid, strerror(errno));
			return -1;
		}
	        if (setreuid(g_ruid, g_ruid)) {
			printf("error setting uid(%d): %s\n",
					g_ruid, strerror(errno));
			return -1;
		}

		if (do_trace(p)) {
			printf("do_trace error\n");
			exit_func();
			return -1;
		}
		return -1;
	}

	/* we will wait on tracer to exit */
	g_newpid = p;
	/* return to relay thread */
	return 0;
}

int main(int argc, char *argv[])
{
	struct termios tms;
	int stdout_logfd;

	g_ruid = getuid();
	g_rgid = getgid();
	g_ptym = -1;
	g_newpid = 0;
	g_daemon = 0;
	g_podflags = 0;
	g_logoutput = 0;
	stdout_logfd = -1;
	g_traceipc[0] = -1;
	g_traceipc[1] = -1;
	g_pty_notify[0] = -1;
	g_pty_notify[1] = -1;
	g_daemon_pipe[0] = -1;
	g_daemon_pipe[1] = -1;
	memset(g_cwd, 0, sizeof(g_cwd));
	memset(g_fcaps, 0, sizeof(g_fcaps));
	memset(g_newroot, 0, sizeof(g_newroot));
	memset(g_nullspace, 0, sizeof(g_nullspace));
	memset(g_pty_slavepath, 0, sizeof(g_pty_slavepath));
	memset(g_podconfig_path, 0, sizeof(g_podconfig_path));
	memset(g_executable_path, 0, sizeof(g_executable_path));

	umask(0027);
	if (getcwd(g_cwd, MAX_SYSTEMPATH) == NULL) {
		printf("getcwd: %s\n", strerror(errno));
		return -1;
	}

	/* create files in root group */
	if (setgid(0)) {
		printf("error setting gid(%d): %s\n", 0, strerror(errno));
		return -1;
	}

	if (downgrade_caps(g_fcaps)) {
		printf("failed to downgrade caps\n");
		return -1;
	}

	if (process_arguments(argc, argv)) {
		return -1;
	}
	if (g_stacksize == 0)
		g_stacksize = DEFAULT_STACKSIZE;

	/* backup original termios */
	tcgetattr(STDIN_FILENO, &g_origterm);
	/* resets tty to original termios at program exit */
	if (atexit(exit_func)) {
		printf("couldn't register exit function\n");
		return -1;
	}

	/* hook up pseudo terminal if not being daemonized */
	if (!g_daemon) {
		if (pipe2(g_pty_notify, O_CLOEXEC)) {
			printf("pipe2: %s\n", strerror(errno));
			return -1;
		}
		setuid(g_ruid);
		if (pty_create(&g_ptym, O_CLOEXEC|O_NONBLOCK, g_pty_slavepath)) {
			printf("could not create pty\n");
			return -1;
		}
		if (setuid(0)) {
			printf("uid error\n");
			return -1;
		}
		/* set terminal to raw mode */
		tcgetattr(STDIN_FILENO, &tms);
		cfmakeraw(&tms);
		/* disable controls chars */
		tms.c_cc[VDISCARD]  = _POSIX_VDISABLE;
		tms.c_cc[VEOF]	    = _POSIX_VDISABLE;
		tms.c_cc[VEOL]	    = _POSIX_VDISABLE;
		tms.c_cc[VEOL2]	    = _POSIX_VDISABLE;
		tms.c_cc[VERASE]    = _POSIX_VDISABLE;
		tms.c_cc[VINTR]	    = _POSIX_VDISABLE;
		tms.c_cc[VKILL]	    = _POSIX_VDISABLE;
		tms.c_cc[VLNEXT]    = _POSIX_VDISABLE;
		tms.c_cc[VMIN]	    = 1;
		tms.c_cc[VQUIT]	    = _POSIX_VDISABLE;
		tms.c_cc[VREPRINT]  = _POSIX_VDISABLE;
		tms.c_cc[VSTART]    = _POSIX_VDISABLE;
		tms.c_cc[VSTOP]	    = _POSIX_VDISABLE;
		tms.c_cc[VSUSP]	    = _POSIX_VDISABLE;
		tms.c_cc[VSWTC]	    = _POSIX_VDISABLE;
		tms.c_cc[VTIME]	    = 0;
		tms.c_cc[VWERASE]   = _POSIX_VDISABLE;
		/* set it! */
		tcsetattr(STDIN_FILENO, TCSANOW, &tms);
		tcflush(STDIN_FILENO, TCIOFLUSH);
	}

	if (create_nullspace())
		return -1;

	if (jettison_readconfig(g_podconfig_path, &g_podflags)) {
		printf("could not configure pod\n");
		return -1;
	}

	if (g_logoutput) {
		stdout_logfd = create_logfile();
		if (stdout_logfd == -1) {
			printf("could not create log file\n");
			return -1;
		}
	}

	if (g_daemon) {
		if (g_tracecalls && ! g_logoutput) {
			printf("no output for --tracecalls option, use --logoutput\n");
			return -1;
		}
		if (g_logoutput) {
			/* use a pipe to better protect log data */
			setuid(g_ruid);
			if (pipe2(g_daemon_pipe, 0)) {
				printf("pipe2: %s\n", strerror(errno));
				return -1;
			}
			if (setuid(0)) {
				printf("uid error\n");
				return -1;
			}
		}
		if (daemonize()) {
			printf("daemonize()\n");
			return -1;
		}
	}

	if (g_tracecalls) {
		if (trace_fork(argv)) {
			printf("error forking trace thread\n");
			return -1;
		}
	}
	else {
		g_newpid = jettison_program(g_executable_path, argv, g_stacksize,
					    g_podflags, NULL, NULL);
		if (g_newpid == -1) {
			printf("jettison failure\n");
			return -1;
		}
	}
	/* switch back to real user credentials */
	if (setregid(g_rgid, g_rgid)) {
		printf("error setting gid(%d): %s\n", g_rgid, strerror(errno));
		return -1;
	}
        if (setreuid(g_ruid, g_ruid)) {
		printf("error setting uid(%d): %s\n", g_ruid, strerror(errno));
		return -1;
	}

	close(g_traceipc[0]);
	close(g_traceipc[1]);
	close(g_daemon_pipe[1]);

	relayio_sigsetup();
	relay_io(stdout_logfd);

	return 0;
}






