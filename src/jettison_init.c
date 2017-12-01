/* (c) Michael R. Tirado -- GPLv3 -- Gnu General Public License version 3
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
		case SIGQUIT:
			terminating = 1;
			break;
		case SIGHUP:
		case SIGUSR1:
		case SIGUSR2:
			kill(-1, signum);
			break;
		default:
			break;
	}
}
/* catch basic termination sigs */
static void sigsetup()
{
	struct sigaction sa;
	terminating = 0;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sighand;

	sigaction(SIGTERM,  &sa, NULL);
	sigaction(SIGQUIT,  &sa, NULL);
	sigaction(SIGINT,   &sa, NULL);
	sigaction(SIGHUP,   &sa, NULL);
	sigaction(SIGUSR1,  &sa, NULL);
	sigaction(SIGUSR2,  &sa, NULL);
}
static void terminator(int retval)
{
	struct timespec request, remain;
	int status;
	int millisec;
	pid_t p;
	printf("terminating with exit status: %d\n", retval);
	kill(-1, SIGTERM);
	/* give programs 10 seconds to exit before killing */
	millisec = 10000;
	while (--millisec >= 0)
	{
		request.tv_sec  = 0;
		request.tv_nsec = 1000000;
		remain.tv_sec   = 0;
		remain.tv_nsec  = 0;
re_sleep:
		if (nanosleep(&request, &remain)) {
			if (errno == EINTR) {
				request.tv_nsec = remain.tv_nsec;
				goto re_sleep;
			}
		}
re_wait:
		p = waitpid(-1, &status, WNOHANG);
		if (p == 0) {
			continue;
		}
		else if (p != -1) {
			printf("exited: %d\n", p);
			goto re_wait;
		}
		else if (p == -1 && errno == ECHILD) {
			break;
		}
	}
	kill(-1, SIGKILL);
	if (terminating)
		retval = -1;
	_exit(retval);
}

/* exec init script/program if env var is set */
int initialize()
{
	char *init_script;
	init_script = eslib_proc_getenv("JETTISON_INIT_SCRIPT");

	if (init_script) {
		int status;
		pid_t p;

		if (eslib_file_path_check(init_script)) {
			printf("init_script bad path\n");
			return -1;
		}

		p = fork();
		if (p == 0) {
			char *args[] = { NULL, NULL };
			if (execve(init_script, args, environ)) {
				printf("exec(%s) %s\n", init_script, strerror(errno));
			}
			return -1;
		}
		else if (p == -1) {
			printf("fork(): %s\n", strerror(errno));
			return -1;
		}
		while (1)
		{
			pid_t rp = waitpid(p, &status, 0);
			if (rp == -1 && errno != EINTR) {
				printf("waitpid: %s\n", strerror(errno));
				return -1;
			}
			else if (rp == p) {
				break;
			}
		}

		if (!WIFEXITED(status) || WEXITSTATUS(status)) {
			printf("initialization failed: %s\n", init_script);
			if (WIFEXITED(status)) {
				printf("exited: %d\n", WEXITSTATUS(status));
			}
			else if (WIFSIGNALED(status)) {
				printf("signalled: %d\n", WTERMSIG(status));
			}
			else {
				printf("unknown: %d\n", status);
			}
			return -1;
		}
	}

	printf("initialized.\n");
	return 0;
}

/* arg[1] should be full program path */
int main(int argc, char *argv[])
{
	char progpath[MAX_SYSTEMPATH];
	char *err = NULL;
	char *traceline;
	char *procname;
	pid_t p;
	pid_t progpid;
	int ipc;

	if (argc < 2) {
		printf("missing arguments\n");
		return -1;
	}

	sigsetup();

	if (es_strcopy(progpath, argv[1], MAX_SYSTEMPATH, NULL))
		return -1;

	/* set process name */
	procname = eslib_proc_getenv("JETTISON_PROCNAME");
	if (procname != NULL) {
		if (es_strcopy(g_procname, procname, MAX_PROCNAME, NULL))
			return -1;
		argv[1] = g_procname;
	}

	ipc = -1;
	errno = 0;
	traceline = eslib_proc_getenv("JETTISON_TRACEFD");
	if (traceline == NULL) {
		if (errno == ENOTUNIQ) {
			printf("bad environment\n");
			return -1;
		}
	}
	else {
		errno = 0;
		ipc = strtol(traceline, &err, 10);
		if (err == NULL || *err || errno) {
			printf("strtol error\n");
			return -1;
		}
	}

	/* if tracing, wait for ack over ipc before exec */
	while(ipc != -1)
	{
		int r;
		char buf = 0;
		r = read(ipc, &buf, 1);
		if (r == -1) {
			if (errno == EINTR || errno == EAGAIN) {
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

	if (initialize()) {
		printf("jettison not calling exec\n");
		return -1;
	}

	progpid = fork();
	if (progpid == -1) {
		printf("fork(): %s\n", strerror(errno));
		return -1;
	}
	else if (progpid == 0) {
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
		if (terminating) {
			terminator(-1);
		}
		p = waitpid(-1, &status, 0);
		if (p == progpid) {
			if (WIFEXITED(status)) {
				if (WEXITSTATUS(status) == 0) {
					/*printf("init: program exited gracefully\n");*/
				}
				else {
					printf("init: program exited unexpectedly\n");
				}
				terminator(WEXITSTATUS(status));
			}
			else {
				printf("init: program abnormally shut down\n");
				terminator(-1);
			}
		}
		else if (p == -1 && errno == ECHILD) {
			printf("error: could not find progpid(%d)\n", progpid);
			return -1;
		}
		else if (p == -1 && errno != EINTR) {
			printf("waitpid: %s\n", strerror(errno));
			return -1;
		}
	}
	printf("impossible!!\n");
	return -1;
}
