/* (c) 2015 Michael R. Tirado -- GPLv3, GNU General Public License, version 3.
 * contact: mtirado418@gmail.com
 *
 * jettison.c
 * wrapper for pod configuration file.
 *
 * read pod configuration file.
 * clone
 * setup pod environment
 * drop privs
 * exec.
 *
 * TODO /tmp as tmpfs option
 * also should create /tmp if missing1!
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
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/mount.h>
#include <fcntl.h>
#include <termios.h>
#include "pod.h"
#include "misc.h"
#include "eslib/eslib.h"

#define MAX_ARGV_LEN 1024 * 16 /* 16KB */
#define IOBUFLEN 4096 * 8 /* 32KB */

#define MAX_PROCNAME 17
#define MAX_OPTLEN 32
/* highest stack value system allows */
#define MAX_SYSTEMSTACK  (1024 * 1024 * 16) /* 16MB */


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
filter_func g_filter;
void *g_filterdata;
char *g_progpath;
char g_procname[MAX_PROCNAME];
int  g_nokill;

int g_newpid;
int g_pty_route;
int g_ptym;


char g_newroot[MAX_SYSTEMPATH];
char g_pty_slavepath[MAX_SYSTEMPATH];



/* must be called first to obtain podflags and chroot path. */
int jettison_readconfig(char *cfg_path, unsigned int *outflags)
{
	g_podflags = 0;
	g_ptym = -1;
	g_newpid = -1;
	return pod_prepare(cfg_path, g_newroot, outflags);
}


/* only valid if jettison_podconfigure has returned 0 ! */
char *jettison_get_newroot()
{
	return g_newroot;
}


/* some heap memory needs to be free'd */
int jettison_abort()
{
	return pod_free();
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
	uid_t ruid;
	gid_t rgid;
	setsid();

	if (g_pty_route == 0) {
		/* no routing, close inherited tty */
		close(STDIN_FILENO);
		close(STDOUT_FILENO);
		close(STDERR_FILENO);
	}
	else if (switch_terminal(g_pty_slavepath, 0)) {
		printf("could not switch to pty(\"%s\")\n", g_pty_slavepath);
		return -1;
	}

	/* enter pod environment */
	if (jettison_initiate(g_podflags) < 0)
		exit(-1);

	/* either call func, or exec */
	if (g_entry) {
		/* TODO for services, drop caps and change uid!!
		 * we need another option allow_pcap so services can use both.
		 * */
		return g_entry(data);
	}
	else {
		char *benv[6] = {
			"PATH=/sbin:/usr/sbin:/bin:/usr/bin:/usr/local/bin",
			"HOME=/podhome",
			"SHELL=/bin/bash",
			"TERM=linux",
			"DISPLAY=:0.0",
			/* TODO, read these from current env for program launcher
			 * or even better, add configuration option for env var
			 * 		^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
			 */
			NULL
		};


		ruid = getuid();
		rgid = getgid();
		printf("\n---------------------------------------------\n");
		printf("what the hay is the realuid?: %d\n", ruid);
		printf("---------------------------------------------\n\n");
		printf("nokill = %d\n", g_nokill);
		if (mkdir("/podhome", 0750)) {
			chmod("/podhome", 0750);
			if (chown("/podhome", ruid, rgid)) {
				printf("home directory error\n");
				return -1;
			}
		}
		chdir("/podhome");
		/* TODO  for cloned entry g_entry services above, we canot use file caps,
		 * so we must drop caps the normal way instead of dropping everything
		 * on a setreuid call, plus we may want to run daemon as uid 0
		 * the drop code is in make_uncapable when you get around to this.
		 */
		if(make_uncapable(g_fcaps)) {
			printf("blocking privileges failed\n");
			return -1;
		}


		if (setregid(rgid, rgid)) {
			printf("error setting gid(%d): %s\n", rgid, strerror(errno));
			return -1;
		}


		/* TODO -- add a makefile defines for ARCH options <<<  XXX !!
		 * */
		if (g_syscall_idx == 0)
			printf("calling exec without seccomp filter\n");
		else if (filter_syscalls(AUDIT_ARCH_I386, g_syscalls,
					 num_syscalls(g_syscalls, MAX_SYSCALLS),
					 g_nokill)) {
			printf("unable to apply seccomp filter\n");
			return -1;
		}

		/* last 2 syscalls granted by seccomp deferred hack.
		 * are always granted if patch not found :(
		 */
		if (setreuid(ruid, ruid)) {
			printf("error setting uid(%d): %s\n", ruid, strerror(errno));
			return -1;
		}
		if (execve(g_progpath, (char **)data, benv) < 0) {
			printf("error: %s\n", strerror(errno));
		}
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

	/* TODO actually test newnet.. */
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
 *  code specifically for command line jettison program
 */
#ifndef STRIP_MAIN_ENTRY

char g_executable_path[MAX_SYSTEMPATH];
char g_podconfig_path[MAX_SYSTEMPATH];
size_t g_stacksize;

/*
 * checks for this program arguments and reorder additional arguments into
 * this threads argv array
 */
int process_arguments(int argc, char *argv[])
{
	unsigned int len;
	int i;
	int argidx = 3;
	char *err;

	/* must have executable path, and pod config file present */
	if (argc < 3)
		goto err_usage;

	g_stacksize = 0;
	g_nokill = 0;
	g_pty_route = 1;

	memset(g_executable_path, 0, sizeof(g_executable_path));
	memset(g_podconfig_path, 0, sizeof(g_podconfig_path));

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


		/* check additional options, and arguments */
		default:

			/* check option length */
			len = strnlen(argv[i], MAX_OPTLEN);
			if (len >= MAX_OPTLEN || len == 0) /* no null terminator */
				goto err_usage;

			if (strncmp(argv[i], "--stacksize", len) == 0) {
				if (argc < i+1 || argv[i+1] == '\0')
					goto missing_opt;
				errno = 0;
				g_stacksize = strtol(argv[++i], &err, 10);
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
				len = strnlen(argv[++i], MAX_PROCNAME);
				if (len >= MAX_PROCNAME) {
					printf("max procname: %d\n", MAX_PROCNAME-1);
					goto bad_opt;
				}
				strncpy(g_procname, argv[i], MAX_PROCNAME-1);
				g_procname[MAX_PROCNAME-1] = '\0';
				argv[0] = g_procname;
				argidx += 2;
			}
			else if (strncmp(argv[i], "--nokill", len) == 0) {
				g_nokill = 1;
				argidx  += 1;
			}
			else if (strncmp(argv[i], "--notty", len) == 0) {
				g_pty_route = 0;
				argidx  += 1;
			}
			break;
		}

	}

	/* no more additional options,  setup new argv */
	i = argidx;
	argidx = 1;
	while(i < argc)
	{
		argv[argidx] = argv[i];
		++argidx;
		++i;
	}

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
	printf("--procname  <process name> set pid1 name\n");
	printf("--stacksize <kilobytes> set maximum stack size\n");
	printf("--nokill    seccomp returns error instead of killing process\n");
	printf("--notty     do not route terminal io, and close stdio\n");
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
	printf("exit_func confirmed\n");
}

/* terminal resize message */
static int handle_sigwinch()
{
	struct winsize w;
	/*char ctchar[128];*/

	if (g_pty_route == 0)
		return 0;

	memset(&w, 0, sizeof(w));
	/* TODO -- squash the curses resize bug :( */
	/*memset(&ctchar, 0, sizeof(ctchar));*/
	/*char ctchar[] = "\0337\033[6n\0338";*/
	/*char ctchar[] = "\0337\033[r\033[999;999H\0338\033[6n";*/
	/* get our main tty size */
	if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &w) == -1)
		return -1;

	/*set pty size */
	if (ioctl(g_ptym, TIOCSWINSZ, &w) == -1)
		return -1;

	/*
	printf("w.row  = %d\n", w.ws_row);
	printf("w.col  = %d\n", w.ws_col);
	printf("w.xpix = %d\n", w.ws_xpixel);
	printf("w.ypix = %d\n", w.ws_ypixel);
	snprintf(ctchar, sizeof(ctchar), "\x1b[8;%d;%d", w.ws_row, w.ws_col);
	write(STDIN_FILENO, ctchar, strnlen(ctchar, sizeof(ctchar)));
	snprintf(ctchar, sizeof(ctchar), "t");
	write(STDIN_FILENO, ctchar, strnlen(ctchar, sizeof(ctchar)));
	*/

	return 0;
}

static void routeio_sighand(int signum)
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
static void routeio_sigsetup()
{
	signal(SIGTERM,   routeio_sighand);
	signal(SIGINT,    routeio_sighand);
	signal(SIGHUP,    routeio_sighand);
	signal(SIGQUIT,   routeio_sighand);
	signal(SIGILL,    routeio_sighand);
	signal(SIGABRT,   routeio_sighand);
	signal(SIGFPE,    routeio_sighand);
	signal(SIGSEGV,   routeio_sighand);
	signal(SIGPIPE,   routeio_sighand);
	signal(SIGALRM,   routeio_sighand);
	signal(SIGUSR1,   routeio_sighand);
	signal(SIGUSR2,   routeio_sighand);
	signal(SIGBUS,    routeio_sighand);
	signal(SIGPOLL,   routeio_sighand);
	signal(SIGIO,     routeio_sighand);
	signal(SIGPROF,   routeio_sighand);
	signal(SIGSYS,    routeio_sighand);
	signal(SIGVTALRM, routeio_sighand);
	signal(SIGXCPU,   routeio_sighand);
	signal(SIGXFSZ,   routeio_sighand);
	signal(SIGIOT,    routeio_sighand);
	signal(SIGSTKFLT, routeio_sighand);
	signal(SIGUNUSED, routeio_sighand);
	signal(SIGTRAP,   routeio_sighand);

	signal(SIGWINCH, routeio_sighand);
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
			printf("fillbuf read: %s\n", strerror(errno));
			return -1;
		}
	}
	return 0;
}



/*
 * route input from ours to theirs,
 * route output from theirs to ours
 * loop until child proc exits, or error
 *
 * in loop, we check if there are bytes in buffer waiting to be written.
 * check write set, and write until buffer has been completely emptied.
 * if the buffer is empty, we check read set to read and refill.
 *
 *
 * XXX -- bugs, some control characters don't work?, home / end in vim?
 *	terminal doesnt seem to be sized right initially ?  open vim, then resize xterm
 *	also that control code that creeps in on xterm resize in bash...
 *	this is kind of buggy...  ugh.
 */
int route_tty(int ours, int theirs)
{
	char rbuf[IOBUFLEN]; /* buffer from them */
	char wbuf[IOBUFLEN]; /* buffer to them */
	unsigned int wpos;   /* current write position */
	unsigned int wbytes; /* number of bytes in read buffer */
	int r;
	int highfd;
	/*int result;*/
	fd_set rds, wrs;
	struct timeval tmr;
	struct timeval instant;


	if (ours == -1 || theirs  == -1)
		return -1;

	if (!isatty(ours) || !isatty(theirs)) {
		printf("route_io not a tty\n");
		return -1;
	}

	memset(&instant, 0, sizeof(instant));
	memset(&tmr, 0, sizeof(tmr));
	tmr.tv_sec = 3;

	/* determine high fd number for select */
	highfd = (theirs > ours)  ? theirs : ours;
	++highfd;

	/* there was some weird issue causing the initial read to be
	 * an IO error, unless we sleep and let other thread open pty?
	 * not 100% sure what was causing it(was on kernel 3.10, now im on 4.1)
	 * i will need to do some more testing to be sure. leaving this here
	 * in case the bug re-appears.
	 */
	/*usleep(350000); -- seems to have been fixed? */
	wpos = 0;
	wbytes = 0;
	memset(rbuf, 0, sizeof(rbuf));
	memset(wbuf, 0, sizeof(wbuf));
	while(1)
	{
		tmr.tv_usec = 0;
		tmr.tv_sec = 3;

		/* wait for event */
		FD_ZERO(&rds);
		FD_ZERO(&wrs);
		FD_SET(ours, &rds);
		FD_SET(ours, &wrs);
		FD_SET(theirs, &wrs);
		FD_SET(theirs, &rds);

		/* waiting on them to consume wbuf */
		if (wbytes) {
			r = select(highfd, NULL, &wrs, NULL, &instant);
			if (r == -1 && errno != EINTR) {
				printf("writeset select(): %s\n", strerror(errno));
				goto fatal;
			}
			if (FD_ISSET(theirs, &wrs)) {
				r = pushbuf(theirs, &wbuf[wpos], wbytes - wpos);
				if (r == -1)
					goto fatal;
				else {
					/* update pos */
					wpos += r;
					if (wpos == wbytes) {
						wpos = 0;
						wbytes = 0;
						continue;
					}
					else if (wpos > wbytes) {
						printf("route io write error\n");
						return -1;
					}
				}
			}
			else {
				/* we could buffer more data until full here
				 *
				 * or maybe just keep this simple and continue
				 * to block reads if they are not reading us.
				 */
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
				if (r == -1)
					goto fatal;
				wbytes = r;
				wpos = 0;
			}

			/* read output from their side and print it */
			if (FD_ISSET(theirs, &rds)) {
				r = fillbuf(theirs, rbuf, sizeof(rbuf)-1);
				if (r == -1)
					goto fatal;
				else if (r > 0) {
					if (pushbuf(STDOUT_FILENO, rbuf, r) == -1)
						goto fatal;
				}
			}
		}

		/*if (waitpid(g_newpid, &result, WNOHANG))
			return 0;*/
	}

fatal:
	printf("strerror: %s\n", strerror(errno));
	return -1;
}


int main(int argc, char *argv[])
{
	unsigned int podflags = 0;
	struct termios tms;
	uid_t ruid = getuid();
	gid_t rgid = getgid();

	if (process_arguments(argc, argv)) {
		return -1;
	}
	if (g_stacksize == 0)
		g_stacksize = DEFAULT_STACKSIZE;

	printf("calling jettison %d \n", g_stacksize);

        if (jettison_readconfig(g_podconfig_path, &podflags)) {
		printf("could not configure pod\n");
		return -1;
	}

	/* backup original termios */
	tcgetattr(STDIN_FILENO, &g_origterm);
	/* reset our tty to original termios at program exit */
	if (atexit(exit_func)) {
		printf("couldn't register exit function\n");
		jettison_abort();
		return -1;
	}

	/* running jettison will hook up a pseudo terminal */
	/* cloned thread will open slave path */
	if (g_pty_route) {
		routeio_sigsetup();
		if (pty_create(&g_ptym, O_CLOEXEC|O_NONBLOCK, g_pty_slavepath)) {
			printf("could not create pty\n");
			jettison_abort();
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

	printf("jettison argv: %s\n", argv[0]);
	g_newpid = jettison_program(g_executable_path, argv, g_stacksize,
			podflags, NULL, NULL);
	if (g_newpid == -1) {
		jettison_abort();
		printf("jettison failure\n");
		return -1;
	}
	handle_sigwinch(); /* set terminal size, stty was reporting 0,0 */
	printf("new pid: %d\n", g_newpid);
	memset(g_fcaps, 0, sizeof(g_fcaps));
	if (make_uncapable(g_fcaps)) {
		printf("make_uncapable failed\n");
		kill(g_newpid, SIGKILL);
		return -1;
	}
	if (setregid(rgid, rgid)) {
		printf("error setting gid(%d): %s\n", rgid, strerror(errno));
		kill(g_newpid, SIGKILL);
		return -1;
	}
        if (setreuid(ruid, ruid)) {
		printf("error setting uid(%d): %s\n", ruid, strerror(errno));
		kill(g_newpid, SIGKILL);
		return -1;
	}
	clear_caps();

	if (g_pty_route) {
		/* route all i/o between stdio and new pty */
		printf("route_tty returned: %d\n",
			route_tty(STDIN_FILENO, g_ptym)
		);
	}
	exit_func();
	return 0;
}
#endif






