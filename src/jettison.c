/* (c) 2015 Michael R. Tirado -- GPLv3, GNU General Public License, version 3.
 * contact: mtirado418@gmail.com
 *
 * jettison.c
 * wrapper for whitelist pod configuration file.
 *
 * TODO: reduce dependency on optional external programs
 * 	 such as tcpdump, xtables
 */

#define _GNU_SOURCE
#include <linux/unistd.h>
#include <sched.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/prctl.h>
#include <fcntl.h>
#include <termios.h>
#include <time.h>
#include "pod.h"
#include "misc.h"
#include "eslib/eslib.h"
#include "eslib/eslib_fortify.h"
#include "eslib/eslib_rtnetlink.h"

#define MAX_ARGV_LEN (1024 * 16) /* 16KB */
#define IOBUFLEN (4096 * 8) /* 32KB */
#define MAX_PROCNAME 17
#define MAX_OPTLEN 32

extern char **environ;
extern int tracecalls(pid_t p, int ipc, char *fortpath); /* tracecalls.c */
extern int netns_setup();

/* pod.c globals */
extern struct pod g_pod;
extern int  g_fcaps[NUM_OF_CAPS];
struct newnet_param g_newnet;
struct seccomp_program g_seccomp_filter;
/* user privilege data, stored in /etc/jettison/user by default */
struct user_privs g_privs;

/* input to clone func */
unsigned int g_podflags;

char *g_progpath;
char g_procname[MAX_PROCNAME]; /* --procname */
char g_pid1name[MAX_PROCNAME];
char g_initscript[MAX_SYSTEMPATH];

int g_daemon; /* --daemon */
int g_logoutput; /* --logoutput */
int g_lognet; /* --lognet */
int g_clear_environ; /* --clear-environ */
int g_stdout_logfd;
int g_daemon_pipe[2]; /* daemon ipc for log fd proxy */

/* seccomp */
long g_retaction;
int  g_strict; /* --strict */
int  g_blocknew; /* --block-new-filters */
int  g_allow_ptrace; /* --allow-ptrace */
int  g_blacklist; /* --blacklist */

/* pod tty i/o */
int g_pty_notify[2];
int g_ptym;

/* for stopping/resuming jettison_init before exec */
int g_traceipc[2];
int g_tracecalls; /* --tracecalls */

uid_t g_ruid;    /* real uid */
gid_t g_rgid;    /* real gid */
pid_t g_mainpid; /* jettison main process */
pid_t g_initpid; /* jettison_init process */

char g_newroot[MAX_SYSTEMPATH];
char g_pty_slavepath[MAX_SYSTEMPATH];
char g_nullspace[MAX_SYSTEMPATH];
char g_executable_path[MAX_SYSTEMPATH];
char g_podconfig_path[MAX_SYSTEMPATH];
char g_cwd[MAX_SYSTEMPATH]; /* directory jettison was called from */
size_t g_stacksize;

/* read and load config, pass1 */
int jettison_readconfig(char *cfg_path, unsigned int *outflags)
{
	char *filename;
	char *pwline;
	char *pwuser;
	filename = eslib_file_getname(cfg_path);
	if (filename == NULL) {
		printf("bad filename\n");
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
	snprintf(g_newroot, MAX_SYSTEMPATH, "%s/%s/%s", POD_PATH, pwuser, filename);
	if (eslib_file_path_check(g_newroot)) {
		printf("bad chroot path\n");
		return -1;
	}
	return pod_prepare(cfg_path, g_newroot, &g_newnet, &g_seccomp_filter,
			g_blacklist, &g_privs, outflags);
}


/* only valid if jettison_podconfigure has returned 0 ! */
char *jettison_get_newroot()
{
	return g_newroot;
}

int create_nullspace()
{
	memset(g_nullspace, 0, sizeof(g_nullspace));
	snprintf(g_nullspace, sizeof(g_nullspace), "%s/.nullspace", POD_PATH);

	if (eslib_file_exists(POD_PATH) != 1) {
		printf("directory missing: %s\n", POD_PATH);
		return -1;
	}
	if (eslib_file_path_check(g_nullspace))
		return -1;

	if (eslib_file_exists(g_nullspace) == 1) {
		if (rmdir(g_nullspace)) {
			printf("could not rmdir %s\n", strerror(errno));
			printf("check that no files were created in %s\n", g_nullspace);
			printf("this should never happen.\n");
			return -1;
		}
	}
	if (eslib_file_mkdirpath(g_nullspace, 0755) != 0) {
		printf("could not create: %s\n", g_nullspace);
		return -1;
	}
	chmod(g_nullspace, 0555);
	return 0;
}

/* uses POD_PATH/.nullspace as chroot directory */
static int downgrade_relay()
{
	struct seccomp_program filter;
	short syscalls[] = {
		__NR__newselect,
		__NR_write,
		__NR_read,
		__NR_kill,
		__NR_waitpid,
		__NR_nanosleep,
		__NR_ioctl, /* TODO whitelist only TIOCWINSZ, it's all we need */
		__NR_close,
		__NR_sigreturn,
		__NR_getppid, /* signal parent with sigwinch if terminal
				 window was resized after jettison */
		__NR_exit,
		__NR_exit_group,
		-1
	};
	seccomp_program_init(&filter);
	if (syscall_list_loadarray(&filter.white, syscalls)) {
		printf("could not load syscalls array\n");
		return -1;
	}
	if (seccomp_program_build(&filter)) {
		printf("seccomp_build failure\n");
		return -1;
	}

	if (eslib_fortify_prepare(g_nullspace, 0)) {
		printf("fortify failed\n");
		return -1;
	}
	setgid(g_rgid);
	if (eslib_fortify(g_nullspace, g_ruid,g_rgid, &filter, 0,0,0,0,  0)) {
		printf("fortify failed\n");
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

	if (eslib_proc_getenv("HOME") == NULL) {
		printf("$HOME is not set\n");
		return -1;
	}
	if (g_clear_environ) {
		char **e = environ;
		while (*e != NULL) {
			*e = NULL;
			++e;
		}
	}

	if (eslib_proc_setenv("HOME", "/podhome")) {
			printf("error setting $HOME\n");
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

int print_options()
{
	char *podfile;
	unsigned int i;
	podfile = eslib_file_getname(g_newroot);
	if (podfile == NULL)
		return -1;

	printf("-----------------------------------------------------------\n");
	printf("\n");
	printf("jettison %s\n", podfile);
	printf("process name: %s\n", g_procname);
	printf("\n");
	/* make note of options */
	if (g_podflags & (1 << OPTION_HOME_EXEC) ) {
		printf("+x /podhome\n");
	}
#ifdef OPTION_X11
	if (g_podflags & (1 << OPTION_X11) ) {
		printf("X11 enabled\n");
	}
#endif
	if (g_podflags & (1 << OPTION_NOPROC) ) {
		printf("no /proc\n");
	}
	if (g_podflags & (1 << OPTION_NEWPTS) ) {
		printf("new pts instance\n");
	}
	printf("\n");
	/* requested capabilities */
	for (i = 0; i < NUM_OF_CAPS; ++i)
	{
		if (g_fcaps[i]) {
			char *name = cap_getname(i);
			printf("can gain %s\n", name);
		}
	}

	printf("\n");
	/* seccomp info */
	printf("seccomp action: ");
	switch (g_retaction)
	{
	case SECCOMP_RET_TRAP:
		printf("trap\n");
		break;
	case SECCOMP_RET_KILL:
		printf("kill\n");
		break;
	case SECCOMP_RET_ERRNO:
		printf("errno\n");
		break;
	}
	if (g_blacklist) {
		printf("    %d blacklisted\n", g_seccomp_filter.black.count);
	}
	else {
		printf("    %d whitelisted\n", g_seccomp_filter.white.count);
		printf("    %d blocked\n", g_seccomp_filter.black.count);
	}
	if (g_seccomp_filter.seccomp_opts & SECCOPT_PTRACE || g_allow_ptrace) {
		printf("    --allow-ptrace\n");
	}
	if (g_seccomp_filter.seccomp_opts & SECCOPT_BLOCKNEW) {
		printf("    --block-new-filters\n");
	}

	printf("\n");
	/* new network namespace */
	if (g_newnet.active) {
		printf("newnet ");
		switch(g_newnet.kind)
		{
		case ESRTNL_KIND_IPVLAN:
			printf("ipvlan\n");
			printf("    interface: (master) %s --> %s (link)\n",
					g_newnet.dev, NEWNET_LINK_NAME);
			printf("    address:   %s/%d\n", g_newnet.addr,g_newnet.netmask);

			break;
		case ESRTNL_KIND_MACVLAN:
			printf("macvlan\n");
			printf("    interface: (master) %s --> %s (link)\n",
					g_newnet.dev, NEWNET_LINK_NAME);
			printf("    macaddr:   %s\n", g_newnet.hwaddr);
			printf("    address:   %s/%d\n", g_newnet.addr,g_newnet.netmask);
			break;
		case ESRTNL_KIND_LOOP:
			printf("loopback\n");
			printf("    interface: lo\n");
			printf("    address:   127.0.0.1\n");
			break;
		case ESRTNL_KIND_UNKNOWN:
			printf("none\n");
			break;
		case ESRTNL_KIND_VETHBR:
			printf("todo.\n");
			break;
		default:
			return -1;
		}
	}
	else {
		printf("notice: using default network namespace\n");
	}
	printf("\n");

	printf("\n");

#ifdef PODROOT_HOME_OVERRIDE
	printf("NOTICE!!! PODROOT_HOME_OVERRIDE is enabled!!!\n");
	printf("this configuration is a hack for system building, and\n");
	printf("probably should only be used for development/testing\n");
	printf("\n");
#endif
	printf("-----------------------------------------------------------\n");
	return 0;
}


/* new thread function */
int jettison_clone_func(void *data)
{
	int fdexempt[4];

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
	if (pod_enter()) {
		printf("pod_enter failure\n");
		return -1;
	}

	change_environ();

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

	chdir("/podhome");

	fdexempt[0] = STDIN_FILENO;
	fdexempt[1] = STDOUT_FILENO;
	fdexempt[2] = STDERR_FILENO;
	fdexempt[3] = g_traceipc[1];
	if (close_descriptors(fdexempt, 4))
		return -1;

	if (g_seccomp_filter.white.count == 0
			&& g_seccomp_filter.black.count == 0
			&& !g_blocknew
			&& g_allow_ptrace) {
		if (print_options())
			return -1;
		printf("**********************************************\n");
		printf("**                WARNING!                  **\n");
		printf("**  calling exec without seccomp filter     **\n");
		printf("**  --blacklist loads systemwide blacklist  **\n");
		printf("**********************************************\n");
	}
	else {
		g_seccomp_filter.retaction = g_retaction;
		g_seccomp_filter.seccomp_opts = 0;
		if (g_blocknew)
			g_seccomp_filter.seccomp_opts |= SECCOPT_BLOCKNEW;
		if (g_allow_ptrace)
			g_seccomp_filter.seccomp_opts |= SECCOPT_PTRACE;
		if (seccomp_program_build(&g_seccomp_filter)) {
			printf("couldn't build seccomp program\n");
			return -1;
		}
		if (print_options())
			return -1;
		if (seccomp_program_install(&g_seccomp_filter)) {
			printf("unable to install seccomp filter\n");
			return -1;
		}
	}
#ifdef PODROOT_HOME_OVERRIDE
	if (execve(((char **)data)[1], ((char **)data)+1, environ) < 0)
		printf("execv failure: %s\n", strerror(errno));
#else
	if (execve(INIT_PATH, (char **)data, environ) < 0)
		printf("jettison_init exec error: %s\n", strerror(errno));
#endif
	return -1;
}

/* clone the current process and return pid
 * returns -1 on error
 *
 * if we want to call exec set func to null, progpath will be the full
 * path to executable file, and data will be argv.
 * */
int jettison_clone(char *progpath, void *data, size_t stacksize, unsigned int podflags)
{
	unsigned int cloneflags;
	char *newstack;
	void *topstack;
	pid_t p;


	if (stacksize > MAX_STACKSIZE) {
		printf("maximum possible stacksize: %d\n", MAX_STACKSIZE);
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
	/* TODO make this a command line argument
	 * if (podflags & (1 << OPTION_ROOTPID))
		cloneflags &= ~CLONE_NEWPID;*/

	if (g_initscript[0] != '\0') {
		eslib_proc_setenv("JETTISON_INIT_SCRIPT", g_initscript);
	}

	/* setup some extra parameters and create new thread */
	g_progpath = progpath;
	g_podflags = podflags;
	p = clone(jettison_clone_func, topstack,
			cloneflags | SIGCHLD, data);
	free(newstack);
	if (p == -1) {
		printf("clone: %s\n", strerror(errno));
		return -1;
	}
	return p;


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

	/* must have executable path, and pod config file present */
	if (argc < 3) {
		if (argc > 1 && strncmp(argv[1], "--listcalls", 12) == 0) {
			syscall_printknown();
			return -1;
		}
		goto err_usage;
	}

	g_stacksize = 0;
	g_retaction = SECCOMP_RET_KILL;
	g_tracecalls = 0;
	g_blocknew = 0;
	g_allow_ptrace = 0;
	g_strict = 0;
	g_blacklist = 0;
	g_clear_environ = 0;

	strncpy(g_pid1name, "jettison_init", sizeof(g_pid1name)-1);
	strncpy(g_procname, argv[1], sizeof(g_procname)-1);

	for (i = 1; i < argc; ++i)
	{
		char *err = NULL;
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
			/* executable path argument */
			if (i == 1) {
				strncpy(g_executable_path, argv[i], MAX_SYSTEMPATH);
				if (eslib_file_path_check(g_executable_path)) {
					printf("bad exec path: %s\n", g_executable_path);
					printf("must be full path to executable\n");
					return -1;
				}
			}
			else if (i == 2) {
				strncpy(g_podconfig_path, argv[i], MAX_SYSTEMPATH);
			}
			else {
				return -1;
			}

			break;

		/* check additional options */
		default:
			len = strnlen(argv[i], MAX_OPTLEN) + 1;
			if (len >= MAX_OPTLEN || len == 0)
				goto err_usage;

			if (strncmp(argv[i], "--stacksize", len) == 0) {
				if (argc < i+1 || argv[i+1] == '\0')
					goto missing_opt;
				errno = 0;
				++i;
				g_stacksize = strtol(argv[i], &err, 10);
				if (err == NULL || *err || errno)
					goto bad_opt;
				g_stacksize *= 1024; /* kilobytes to bytes */
				if (g_stacksize > MAX_STACKSIZE) {
					printf("maximum stacksize is %d KB\n",
							MAX_STACKSIZE/1024);
					goto bad_opt;
				}
				argidx += 2;
			}
			else if (strncmp(argv[i], "--procname", len) == 0
					|| strncmp(argv[i], "-p", len) == 0) {
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
				argidx += 2;
			}
			else if (strncmp(argv[i], "--strict", len) == 0) {
				if (g_tracecalls) {
					printf("can't use --strict with --tracecalls\n");
					return -1;
				}
				g_strict = 1;
				argidx  += 1;
			}
			else if (strncmp(argv[i], "--tracecalls", len) == 0) {
				if (g_strict) {
					printf("can't use --tracecalls with --strict\n");
					return -1;
				}
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
			else if (strncmp(argv[i], "--lognet", len) == 0) {
				/*
				 * arg 1 - log filesize
				 *         0 count is ignored, single huge file.
				 *       >=1 file is limited
				 * arg 2 - number of log rotation files
				 *       >=2 log is rotated (truncated)
				 */
				if (argc < i+2 || argv[i+1] == '\0' || argv[i+2] == 0) {
					printf("--lognet requires size & count args\n");
					goto missing_opt;
				}
				/* read log file size */
				errno = 0;
				++i;
				g_newnet.log_filesize = strtol(argv[i], &err, 10);
				if (err == NULL || *err || errno)
					goto bad_opt;
				if (g_newnet.log_filesize < 0) {
					goto bad_opt;
				}
				/* read rotation count */
				errno = 0;
				++i;
				g_newnet.log_count = strtol(argv[i], &err, 10);
				if (err == NULL || *err || errno)
					goto bad_opt;
				if (g_newnet.log_count != 0 && g_newnet.log_filesize > 0
						&& g_newnet.log_count < 2)
					goto bad_opt;

				g_lognet = 1;
				argidx  += 3;
			}
			else if (strncmp(argv[i], "--blacklist", len) == 0) {
				g_blacklist = 1;
				argidx  += 1;
			}
			else if (strncmp(argv[i], "--listcalls", len) == 0) {
				syscall_printknown();
				return -1;
			}
			else if (strncmp(argv[i], "--clear-environ", len) == 0) {
				g_clear_environ = 1;
				argidx += 1;
			}
			else if (strncmp(argv[i], "--init", len) == 0) {
				++i;
				strncpy(g_initscript, argv[i], MAX_SYSTEMPATH);
				if (eslib_file_path_check(g_initscript)) {
					printf("init script must be an asbolute ");
					printf("pod-local path, eg: /podhome/init.sh\n");
					return -1;
				}
				argidx += 2;
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

	if (g_tracecalls) {
		/* always block new filters to prevent spoofed data */
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
	printf("--procname <name>\n");
	printf("        -p <name>\n");
	printf("        set new process name\n");
	printf("\n");
	printf("--stacksize  <kilobytes>\n");
	printf("        set new process stack size\n");
	printf("\n");
	printf("--strict\n");
	printf("        seccomp fail kills process instead of ENOSYS error\n");
	printf("\n");
	printf("--listcalls\n");
	printf("        list all systemcalls jettison knows about\n");
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
	printf("\n");
	printf("--daemon\n");
	printf("        orphan process and disconnect tty\n");
	printf("\n");
	printf("--logoutput\n");
	printf("        write stdout/stderr to a timestamped log file in cwd\n");
	printf("\n");
	printf("--lognet <size> <count>\n");
	printf("        dump .pcap file(s) for ipvlan / macvlan traffic\n");
	printf("        <size> is individual log file size in megabytes, if 0\n");
	printf("        the log file will not be limited.\n");
	printf("        <count> >= 2 means log will be rotated and numbered\n");
	printf("        with up to <count> files backlog.\n");
	printf("\n");
	printf("--blacklist\n");
	printf("        use system blacklist instead of pod config file\n");
	printf("\n");
	printf("--clear-environ\n");
	printf("        clear environment before calling exec\n");
	printf("\n");
	printf("--init <init-script>\n");
	printf("        run this script before running executable.\n");
	printf("        must be a pod-local path, eg: /podhome/.pods/browserA.sh\n");
	printf("        which should be whitelisted using home rx /.pods/browserA.sh\n");
	printf("\n");
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
	pid_t ppid;
	if (g_initpid > 0)
		kill(g_initpid, SIGTERM);
	if (g_newnet.log_pid > 0)
		kill(g_newnet.log_pid, SIGTERM);
	usleep(500000);
	/* net logger needs some time to write data */
	if (g_newnet.log_pid > 0) {
		int i = 0;
		int status;
		/* this is sitting in a new net namespace,
		 * make sure it's killed if it hangs > 5 seconds */
		while (1)
		{
			pid_t p = waitpid(g_newnet.log_pid, &status, WNOHANG);
			if (p == g_newnet.log_pid)
				break;
			else if (p == -1 && errno == ECHILD)
				break;
			else if (p != 0 || ++i >= 50) {
				kill(g_newnet.log_pid, SIGKILL);
				break;
			}
			usleep(100000);
			printf("waiting for netlog(%d) to shutdown\n", g_newnet.log_pid);
		}
	}

	tcsetattr(STDIN_FILENO, TCSANOW, &g_origterm);

	ppid = getppid();
	if (ppid < 1)
		printf("getppid(): %s\n", strerror(errno));
	else if (kill(ppid, SIGWINCH))
		printf("kill(%d, SIGWINCH): %s\n", getppid(), strerror(errno));

	printf("jettison_exit\n");
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
	switch (signum)
	{
	case SIGWINCH:
		handle_sigwinch();
		break;
	case SIGTERM:
	case SIGHUP:
	case SIGUSR1:
	case SIGUSR2:
	case SIGQUIT:
		if (g_initpid > 0)
			kill(g_initpid, signum);
		break;
	default:
		exit_func();
		_exit(-1);
		break;
	}
}

/* catch fatal signals, short of a sigkill */
static void relayio_sigsetup()
{
	signal(SIGINT,    relayio_sighand);
	signal(SIGILL,    relayio_sighand);
	signal(SIGABRT,   relayio_sighand);
	signal(SIGFPE,    relayio_sighand);
	signal(SIGSEGV,   relayio_sighand);
	signal(SIGPIPE,   relayio_sighand);
	signal(SIGALRM,   relayio_sighand);
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

	/* forward these */
	signal(SIGTERM,   relayio_sighand);
	signal(SIGHUP,    relayio_sighand);
	signal(SIGUSR1,   relayio_sighand);
	signal(SIGUSR2,   relayio_sighand);
	signal(SIGQUIT,   relayio_sighand);

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
			else if (count > size)
				return -1;
		}
		else if (r == 0 || (r < 0 && (errno == EINTR || errno == EAGAIN))) {
			usleep(500);
		}
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
		if (r >= 0)
			return r;
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
	int status;
	int canwrite = 1;
	unsigned char estatus = -1;

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
		if(downgrade_relay()) {
			printf("failed to downgrade relay\n");
			return -1;
		}
		/* daemon update loop */
		while (1)
		{
			tmr.tv_usec = 0;
			tmr.tv_sec = 10;
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
					continue;
				}
				else if (r == 0) {
					printf("daemon_pipe EOF\n");
					return -1;
				}
				else {
					printf("daemon_pipe error: %s\n",
							strerror(errno));
					return -1;
				}
			}
			if (waitpid(-1, &status, WNOHANG) == -1) {
				close(stdout_logfd);
				return 0;
			}
		}
	}

	/* non-daemon, route tty normally */
	handle_sigwinch(); /* set terminal size */
	if(downgrade_relay()) {
		printf("failed to downgrade relay\n");
		return -1;
	}
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

	canwrite = 1;
	/* normal pty io relay */
	while(1)
	{
		pid_t p;
		tmr.tv_usec = 0;
		tmr.tv_sec = 10;

		p = waitpid(-1, &status, WNOHANG);
		if (p > 1) {
			if (p == g_initpid) {
				wbytes = 0;
				canwrite = 0;
				if (WIFEXITED(status)) {
					estatus = WEXITSTATUS(status);
					if (estatus == 0) {
						printf("init exited normally ");
					}
					else {
						printf("init exited abnormally ");
					}
					printf("with status: %d\n", estatus);
				}
				else {
					printf("init shut down abnormally\n");
					estatus = -1;
				}
				g_initpid = 0;
			}
			else if (p == g_newnet.log_pid) {
				if (g_initpid > 0) {
					/* netlogger was interrupted,  TODO:
					 * make an option for this kill behavior
					 * and use in strict mode, otherwise huge
					 * warning message should be displayed. */
					if (kill(g_initpid, SIGTERM)) {
						printf("kill %d %s\n",g_initpid,
								strerror(errno));
						return -1;
					}
					g_newnet.log_pid = 0;
				}
			}
		}
		/* waiting on them to consume wbuf */
		if (wbytes && canwrite) {
			FD_ZERO(&wrs);
			FD_SET(theirs, &wrs);
			r = select(theirs+1, NULL, &wrs, NULL, &instant);
			if (r == -1) {
				if (errno != EINTR) {
					printf("writeset select(): %s\n",
							strerror(errno));
					goto fatal;
				}
				else {
					continue;
				}
			}
			if (FD_ISSET(theirs, &wrs)) {
				r = pushbuf(theirs, &wbuf[wpos], wbytes - wpos);
				if (r == -1) {
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
						goto fatal;
					}
				}
			}
		}
		else {
			FD_ZERO(&rds);
			FD_SET(ours, &rds);
			FD_SET(theirs, &rds);
			/* check read set for input wait until data is ready. */
			r = select(highfd, &rds, NULL, NULL, &tmr);
			if (r == -1) {
				if (errno != EINTR) { /* we have a sighandler for this */
					printf("select(): %s\n", strerror(errno));
					goto fatal;
				}
				else {
					continue;
				}
			}
			/* read output from their side and print it */
			if (FD_ISSET(theirs, &rds)) {
				r = fillbuf(theirs, rbuf, sizeof(rbuf)-1);
				if (r == -1) {
					goto fatal;
				}
				else if (r > 0) {
					if (pushbuf(STDOUT_FILENO, rbuf, r) == -1) {
						goto fatal;
					}
					if (stdout_logfd != -1) {
						if (logwrite(stdout_logfd, rbuf, r)) {
							goto fatal;
						}
					}
				}
			}
			/* read input from our side, and buffer it */
			if (FD_ISSET(ours, &rds)) {
				r = fillbuf(ours, wbuf, sizeof(wbuf)-1);
				if (r == -1 || r == 0) {
					goto fatal;
				}
				wbytes = r;
				wpos = 0;
			}
		}
	}

fatal:
	/*  get exit status */
	if (g_initpid > 0) {
		int millisec = 12000;
		kill(g_initpid, SIGTERM);
		/* give pod enough time to completely shutdown */
		while (--millisec >= 0)
		{
			pid_t p;
			struct timespec request, remain;
			request.tv_sec  = 0;
			request.tv_nsec = 1000000;
			remain.tv_sec   = 0;
			remain.tv_nsec  = 0;
re_sleep:
			if (nanosleep(&request, &remain)) {
				if (errno == EINTR) {
					request.tv_sec  = remain.tv_sec;
					request.tv_nsec = remain.tv_nsec;
					goto re_sleep;
				}
			}
			p = waitpid(g_initpid, &status, WNOHANG);
			if (p == g_initpid) {
				if (WIFEXITED(status)) {
					estatus = WEXITSTATUS(status);
				}
				else {
					estatus = -1;
				}
				break;
			}
			else if (p == -1 && errno == ECHILD) {
				estatus = -1;
				break;
			}
		}
	}
	/*printf("relay_done: exit status=%d\n", estatus);*/
	return estatus;
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
	int r;

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
	r = eslib_file_exists(logpath);
	if (r == -1 ) {
		printf("logfile error\n");
		return -1;
	}
	else if (r != 0) {
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
		printf("daemon forked");
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

	if (tracecalls(tracee, g_traceipc[0], g_nullspace)) {
		printf("tracecalls error: %d\n", tracee);
		_exit(-1);
	}
	printf("error\n");
	_exit(-1);
}

/* tracer should be parent of cloned thread
 */
static int trace_fork(char **argv)
{
	int ipc[2];
	pid_t p;
	mode_t origmask;

	origmask = umask(0027);
	if (pipe2(ipc, O_CLOEXEC)) {
		printf("trace pipe2: %s\n", strerror(errno));
		return -1;
	}
	umask(origmask);

	p = fork();
	if (p == -1) {
		return -1;
	}
	else if (p == 0) {
		char buf[64];

		close(ipc[0]);
		setuid(g_ruid);
		origmask = umask(0027);
		if (socketpair(AF_UNIX, SOCK_STREAM, 0, g_traceipc)) {
			printf("socketpair: %s\n", strerror(errno));
			return -1;
		}
		umask(origmask);
		setuid(0);

		snprintf(buf, sizeof(buf), "%d", g_traceipc[1]);
		if (eslib_proc_setenv("JETTISON_TRACEFD", buf)) {
			printf("setenv error\n");
			return -1;
		}

		argv[0] = g_pid1name;
		p = jettison_clone(g_executable_path, argv, g_stacksize, g_podflags);

		close(g_traceipc[1]);
		close(g_daemon_pipe[0]);
		close(g_daemon_pipe[1]);
		close(g_pty_notify[0]);
		close(g_pty_notify[1]);
		close(g_ptym);

		if (p == -1) {
			printf("jettison failed\n");
			return -1;
		}

		/* send pid back to main thread */
		while(write(ipc[1], &p, sizeof(p)) == -1)
		{
			if (errno != EINTR) {
				printf("write: %s\n", strerror(errno));
				return -1;
			}
		}
		if (setregid(g_rgid, g_rgid)) {
			printf("error setting gid(%d): %s\n", g_rgid, strerror(errno));
			return -1;
		}
	        if (setreuid(g_ruid, g_ruid)) {
			printf("error setting uid(%d): %s\n", g_ruid, strerror(errno));
			return -1;
		}
		if (do_trace(p)) {
			printf("do_trace error\n");
			exit_func();
			return -1;
		}
		return -1;
	}

	/* get pid for graceful shutdown */
	while(1)
	{
		int r = read(ipc[0], &p, sizeof(p));
		if (r == sizeof(p))
			break;
		else if (r == -1 && errno == EINTR)
			continue;
		else {
			printf("read(%d): %s\n", r, strerror(errno));
			return -1;
		}
	}
	close(ipc[0]);
	close(ipc[1]);
	g_initpid = p;
	return 0;
}

#ifdef POD_INIT_CMDR
#include "init_cmdr.h"
static int permit_gizmo(char *name)
{
	unsigned int len = strnlen(name, JETTISON_CMDR_MAXNAME);
	struct gizmo *giz = cmdr_find_gizmo(name, len);
	if (giz) {
		giz->executable = 1;
		return 0;
	}
	else {
		printf("gizmo not found: %s\n", name);
		return 0;
	}
	return -1;
}
#endif

/*
 *  performs some checks here for pass1 privileges (newpts, net addresses, etc)
 *  user_privs is filled out here.
 */
int process_user_permissions()
{
	unsigned int line_num = 0;
	size_t fpos = 0;
	size_t flen = 0;
	char *fbuf = NULL;
	char *pwline;
	char *pwuser;
	char fpath[MAX_SYSTEMPATH];
	char netaddr[19];
	unsigned int ipvlan_check = 0;
	unsigned int ipvlan_limit = 0;
	unsigned int devmatch = 0;
	unsigned int macmatch = 0;
	unsigned int ipmatch = 0;

	memset(&g_privs, 0, sizeof(g_privs));

	/* get username for file path */
	pwline = passwd_fetchline(g_ruid);
	if (pwline == NULL) {
		printf("passwd file error\n");
		return -1;
	}
	pwuser = passwd_getfield(pwline, PASSWD_USER);
	if (pwuser == NULL) {
		printf("could not find username in passwd file\n");
		return -1;
	}

	if (g_newnet.kind==ESRTNL_KIND_IPVLAN || g_newnet.kind==ESRTNL_KIND_MACVLAN) {
		ipvlan_check = 1;
	}
	snprintf(netaddr, sizeof(netaddr), "%s/%s", g_newnet.addr, g_newnet.prefix);
	snprintf(fpath, sizeof(fpath), "%s/%s", JETTISON_USERCFG, pwuser);

	fbuf = malloc(4096);
	if (fbuf == NULL)
		return -1;
	if (eslib_file_read_full(fpath, fbuf, 4096 - 1, &flen)) {
		if (errno == EOVERFLOW && flen > 0) {
			fbuf = realloc(fbuf, flen + 1);
			if (fbuf == NULL)
				return -1;
			if (eslib_file_read_full(fpath, fbuf, flen, &flen)) {
				printf("could not read file\n");
				free(fbuf);
				return -1;
			}
		}
		else {
			printf("problem reading file(%s): %s\n", fpath, strerror(errno));
			goto err_free;
		}
	}
	fbuf[flen] = '\0';

	while (fpos < flen)
	{
		char *line;
		unsigned int linepos = 0;
		unsigned int linelen = 0;
		unsigned int advance;
		char *keyword = NULL;
		char *param = NULL;
		int lim;

		line = &fbuf[fpos];
		++line_num;

		linelen = eslib_string_linelen(line, flen - fpos);
		if (linelen >= flen - fpos) {
			printf("bad line\n");
			goto err_free;
		}
		else if (linelen == 0) { /* blank line */
			++fpos;
			continue;
		}

		if (line[0] == '#') { /* comment */
			fpos += linelen + 1;
			continue;
		}

		if (!eslib_string_is_sane(line, linelen)) {
			printf("invalid line(%d){%s}\n", *line, line);
			goto err_free;
		}
		if (eslib_string_tokenize(line, linelen, " \t")) {
			printf("tokenize failed\n");
			goto err_free;
		}

		/*
		 *  parse privilege file
		 *  ipaddr  <address/mask> - occupy this ip/netmask
		 *  macaddr <address>      - occupy this macaddr
		 *  iplimit <count>        - maximum number of ip's user can use.
		 *  newpts                 - create new pts instances
		 *  gizmo   <name>	   - some gizmos need caps that may cause trouble
		 */
		keyword = eslib_string_toke(line, linepos, linelen, &advance);
		linepos += advance;
		if (keyword == NULL) { /* only tabs/spaces on line */
			fpos += linelen + 1;
			continue;
		}
		param = eslib_string_toke(line, linepos, linelen, &advance);
		linepos += advance;

		if (strncmp(keyword, "iplimit", 8) == 0) {
			if (param == NULL)
				goto err_param_free;
			if (ipvlan_limit) {
				printf("duplicate limit entries\n");
				goto err_free;
			}
			if (eslib_string_to_int(param, &lim) || lim <= 0) {
				printf("bad limit value\n");
				goto err_free;
			}
			ipvlan_limit = lim;
		}
		else if (strncmp(keyword, "ipaddr", 7) == 0) {
			if (param == NULL)
				goto err_param_free;
			if (strncmp(param, netaddr, sizeof(netaddr)) == 0)
				ipmatch = 1;
		}
		else if (strncmp(keyword, "netdev", 7) == 0) {
			if (param == NULL)
				goto err_param_free;
			if (strncmp(param, g_newnet.dev, sizeof(g_newnet.dev)) == 0)
				devmatch = 1;
		}
		else if (strncmp(keyword, "macaddr", 8) == 0) {
			if (param == NULL)
				goto err_param_free;
			if (strncmp(param, g_newnet.hwaddr, sizeof(g_newnet.hwaddr)) == 0)
				macmatch = 1;
		}
		else if (strncmp(keyword, "newpts", 7) == 0) {
			g_privs.newpts = 1;
		}
		else if (strncmp(keyword, "gizmo", 6) == 0) {
#ifdef POD_INIT_CMDR
			if (param == NULL)
				goto err_param_free;
			if (permit_gizmo(param))
				goto err_free;
#endif
		}
		else {
			printf("bad keyword: %s\n", keyword);
			goto err_free;
		}

		fpos += linelen + 1;
		if (fpos > flen)
			goto err_free;
		else if (fpos == flen)
			break;
	}

	free(fbuf);
	fbuf = NULL;

	/* verify privileges on network resources */
	if (ipvlan_check) {
		if (ipvlan_limit == 0) {
			printf("user privilege file does not contain limit entry\n");
			return -1;
		}
		if (ipvlan_limit >= JETTISON_IPVLAN_LIMIT) {
			printf("ipvlan hard limit: %d", JETTISON_IPVLAN_LIMIT);
			return -1;
		}
		if (!ipmatch) {
			printf("ip %s/%s not found in user privilege file\n",
					g_newnet.addr, g_newnet.prefix);
			return -1;
		}
		if (!devmatch) {
			printf("netdev %s not found in user privilege file\n",
					g_newnet.dev);
			return -1;
		}
		if (g_newnet.kind == ESRTNL_KIND_MACVLAN) {
			if (!macmatch) {
				printf("macaddr %s not found in user privilege file\n",
						g_newnet.hwaddr);
				return -1;
			}
		}
		g_privs.ipvlan_limit = ipvlan_limit;
	}
	return 0;

err_param_free:
	printf("missing parameter\n");
err_free:
	printf("error in %s, line %d\n", fpath, line_num);
	free(fbuf);
	return -1;
}

int main(int argc, char *argv[])
{
	struct termios tms;
	int stdout_logfd;

	g_ruid = getuid();
	g_rgid = getgid();
	g_mainpid = getpid();
	g_ptym = -1;
	g_daemon = 0;
	g_initpid = 0;
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
	memset(&g_newnet, 0, sizeof(g_newnet));
	memset(g_newroot, 0, sizeof(g_newroot));
	memset(g_procname, 0, sizeof(g_procname));
	memset(g_pid1name, 0, sizeof(g_pid1name));
	memset(g_nullspace, 0, sizeof(g_nullspace));
	memset(g_initscript, 0, sizeof(g_initscript));
	memset(g_pty_slavepath, 0, sizeof(g_pty_slavepath));
	memset(g_podconfig_path, 0, sizeof(g_podconfig_path));
	memset(g_executable_path, 0, sizeof(g_executable_path));
	seccomp_program_init(&g_seccomp_filter);

	if (process_arguments(argc, argv)) {
		return -1;
	}

	/* create files in root group */
	if (setgid(0)) {
		printf("error setting gid(%d): %s\n", 0, strerror(errno));
		return -1;
	}

	if (getcwd(g_cwd, MAX_SYSTEMPATH) == NULL) {
		printf("getcwd: %s\n", strerror(errno));
		return -1;
	}

	if (downgrade_caps()) {
		printf("failed to downgrade caps\n");
		return -1;
	}

	if (g_stacksize == 0) {
		g_stacksize = DEFAULT_STACKSIZE;
	}
	else if (g_stacksize < MIN_STACKSIZE) {
		printf("stacksize too small, minimum is %d KB\n", MIN_STACKSIZE/1024);
		return -1;
	}

	/* empty directory */
	if (create_nullspace())
		return -1;

#ifdef POD_INIT_CMDR
	load_gizmos();
#endif

	setuid(g_ruid); /* to read cwd (without DAC_OVERRIDE) */
	if (jettison_readconfig(g_podconfig_path, &g_podflags)) {
		return -1;
	}
	/* fill out g_privs */
	if (process_user_permissions()) {
		return -1;
	}
	setuid(0);

	if (g_lognet) {
		if (g_newnet.kind != ESRTNL_KIND_IPVLAN
				&& g_newnet.kind != ESRTNL_KIND_MACVLAN) {
			printf("--lognet requires use of newnet ipvlan or macvlan\n");
			return -1;
		}
	}

	/* backup original termios */
	tcgetattr(STDIN_FILENO, &g_origterm);
	/* resets tty to original termios at program exit */
	if (atexit(exit_func)) {
		printf("couldn't register exit function\n");
		return -1;
	}


	/* hook up pseudo terminal if not being daemonized */
	if (!g_daemon) {
		mode_t origmask = umask(0027);
		if (pipe2(g_pty_notify, O_CLOEXEC)) {
			printf("pipe2: %s\n", strerror(errno));
			return -1;
		}
		umask(origmask);
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
			mode_t origmask;
			/* use a pipe to better protect log data */
			setuid(g_ruid);
			origmask = umask(0027);
			if (pipe2(g_daemon_pipe, 0)) {
				printf("pipe2: %s\n", strerror(errno));
				return -1;
			}
			umask(origmask);
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

	/* set procname for pid1 to read */
	if (eslib_proc_setenv("JETTISON_PROCNAME", g_procname)) {
		printf("error setting process name\n");
		return -1;
	}

	/* setup network namespace */
	if(g_newnet.active) {
		if (netns_setup()) {
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
		argv[0] = g_pid1name;
		g_initpid = jettison_clone(g_executable_path, argv,
					g_stacksize, g_podflags);
		if (g_initpid == -1) {
			printf("jettison failure\n");
			return -1;
		}
	}
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
	return relay_io(stdout_logfd);
}

