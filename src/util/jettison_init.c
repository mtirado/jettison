/* (c) Michael R. Tirado -- GPLv3 -- Gnu General Public License version 3
 *
 * namespace init.
 *
 * We need an init program to register signals, otherwise they are not sent
 * to this namespace. also to halt program until tracecalls is ready.
 *
 * if you want to use an external trace program,
 * it would be best to use a wrapper to launch in a stopped state before
 * attaching from an ancestor process, and having your tracer continue it.
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include "../eslib/eslib.h"

extern char **environ;

static void sighand(int signum)
{
	/* TODO send sigterm to every process ?
	 * will require kill to be whitelisted though, hmmm.. */
	printf("jettison_init got signal: %d\n", signum);
}
/* catch basic termination sigs */
static void sigsetup()
{
	signal(SIGTERM, sighand);
	signal(SIGINT,  sighand);
	signal(SIGHUP,  sighand);
	signal(SIGQUIT, sighand);
}

/* arg[1] should be full program path */
int main(int argc, char *argv[])
{
	char *err = NULL;
	char *traceline;
	pid_t p;
	int ipc;

	if (argc < 2) {
		printf("missing arguments\n");
		return -1;
	}

	/*
	 * pidns 1 process blocks all unregistered signals to children
	 * which is less than ideal for handling shutdown/reboot sigterm
	 * TODO -- add more signals through config file / environ
	 */
	sigsetup();

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
		if (execve(argv[1], &argv[1], environ)) {
			printf("exec(%s) error: %s\n", argv[1], strerror(errno));
		}
		return -1;
	}

	/* handle our initly duties */
	while (1)
	{
		int status;
		p = waitpid(-1, &status, 0);
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












