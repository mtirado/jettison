/* (c) Michael R. Tirado -- GPLv3 -- Gnu General Public License version 3
 *
 * namespace init.
 *
 * we register at least SIGTERM to let a user gracefully shut down entire
 * running pod without any messy plumbing. give programs 10 seconds to exit
 * before pid1 exits.
 *
 * if you want to use an external trace program,
 * it would be best to use a wrapper to launch in a stopped state before
 * attaching from an ancestor process, and having your tracer continue it.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include "eslib/eslib.h"
#define MAX_PROCNAME 17

extern char **environ;
char g_procname[MAX_PROCNAME];
sig_atomic_t terminating;
static void sighand(int signum)
{
	switch (signum)
	{
		case SIGTERM:
		case SIGINT:
		case SIGHUP:
		case SIGQUIT:
			terminating = 1;
			break;
		default:
			break;
	}
}
/* catch basic termination sigs */
static void sigsetup()
{
	terminating = 0;
	signal(SIGTERM, sighand);
	signal(SIGQUIT, sighand);
	signal(SIGINT,  sighand);
	signal(SIGHUP,  sighand);
}
static void terminator()
{
	int i, status;
	pid_t p;
	printf("propagating termination signal\n");
	kill(-1, SIGTERM);
	/* give programs 10ish seconds to exit */
	for (i = 0; i < 1000; ++i) {
		usleep(10000);
		p = waitpid(-1, &status, WNOHANG);
		if (p == 0) {
			continue;
		}
		else if (p != -1) {
			printf("exited: %d\n", p);
		}
		else if (p == -1 && errno == ECHILD) {
			break;
		}
	}
	printf("terminating.\n");
	kill(-1, SIGKILL);
	_exit(0);
}

/* arg[1] should be full program path */
int main(int argc, char *argv[])
{
	char progpath[MAX_SYSTEMPATH];
	char *err = NULL;
	char *traceline;
	char *procname;
	pid_t p;
	int ipc;

	if (argc < 2) {
		printf("missing arguments\n");
		return -1;
	}

	sigsetup();

	strncpy(progpath, argv[1], MAX_SYSTEMPATH-1);
	progpath[MAX_SYSTEMPATH-1] = '\0';

	/* set process name */
	procname = eslib_proc_getenv("JETTISON_PROCNAME");
	printf("init got procname: %s\n", procname);
	if (procname != NULL) {
		int len = strnlen(procname, MAX_PROCNAME);
		if (len >= MAX_PROCNAME) {
			printf("invalid procname\n");
			return -1;
		}
		strncpy(g_procname, procname, MAX_PROCNAME-1);
		g_procname[MAX_PROCNAME-1] = '\0';
		argv[1] = g_procname;
	}

	ipc = -1;
	traceline = eslib_proc_getenv("JETTISON_TRACEFD");
	if (traceline == NULL) {
		if (errno == ENOTUNIQ) {
			printf("bad environment\n");
			return -1;
		}
	}
	else if (traceline) {
		errno = 0;
		printf("traceline: %s\n", traceline);
		ipc = strtol(traceline, &err, 10);
		if (*err || errno) {
			printf("strtol error\n");
			return -1;
		}
	}

	/* wait for ack over ipc before execution */
	while(ipc != -1)
	{
		int r;
		char buf = 0;
		r = read(ipc, &buf, 1);
		if (r == -1) {
			if (errno == EINTR || errno == EAGAIN) {
				printf("ticking\n");
				continue;
			}
			printf("trace ipc error: %s\n",	strerror(errno));
			return -1;
		}
		else if (buf == 'K') {
			break;
		}
		else {
			printf("\nr=%d errno: %s\n", r, strerror(errno));
			printf("bad ipc msg\n");
			return -1;
		}
	}
	close(ipc);

	p = fork();
	if (p == -1) {
		printf("fork(): %s\n", strerror(errno));
		return -1;
	}
	else if (p == 0) {
		/* that's all folks */
		if (execve(progpath, &argv[1], environ)) {
			printf("exec(%s) error: %s\n", argv[1], strerror(errno));
		}
		return -1;
	}

	/* handle our initly duties */
	while (1)
	{
		int status;
		p = waitpid(-1, &status, WNOHANG);
		usleep(1000);
		if (terminating)
			terminator();
		if (p == -1 && errno == ECHILD) {
			printf("fin.\n");
			return 0;
		}
		else if (p == -1) {
			printf("waitpid: %s\n", strerror(errno));
			return -1;
		}
	}
	printf("impossible!!\n");
	return -1;
}
