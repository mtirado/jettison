/* (c) Michael R. Tirado -- GPLv3 -- Gnu General Public License version 3
 *
 * launch program passed in as argv[1] after we receive ipc go-ahead.
 *
 * usage: ipc socket is a socketpair used to translate pid's between namespaces
 * 	  this is intended to be forked with ipc fdnum at end of process name
 * 	  in order to preserve arguments that need to be passed to program.
 * 	  set the name to trace7 for example, in argv[0] before exec
 * 	  and make sure socket does not have O_CLOEXEC set.
 *
 * if you want to use an external tracer program, this will not be much help.
 * it would be best to use a wrapper to launch in a stopped state before
 * attaching, and having your tracer continue it.
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
extern char **environ;

struct ucred;
extern int eslib_sock_send_cred(int sock);
extern int eslib_sock_recv_cred(int sock, struct ucred *out_creds);

/* arg[1] should be full program path */
int main(int argc, char *argv[])
{
	int ipc;
	char *err;

	if (argc < 2) {
		printf("missing arguments\n");
		return -1;
	}

	ipc = -1;
	/* ipc fdnum is stowed in process name to preserve arguments */
	if (strncmp(argv[0], "trace", 5) == 0) {
		errno = 0;
		ipc = strtol(&argv[0][5], &err, 10);
		if (*err || errno) {
			printf("strtol error\n");
			return -1;
		}
		argv[2] = NULL;
	}

	if (ipc == -1) {
		printf("ipc fd error\n");
		return -1;
	}
	else {
		char buf[128];
		sprintf(buf, "ls -l /proc/%d/fd", getpid());
		printf("\n\nipc: %d\n", ipc);
		system(buf);
	}

	/* wait for ack over ipc before execution */
	while(1)
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

	printf("tracee exec\n");
	if (execve(argv[1], &argv[1], environ)) {
		printf("exec(%s) error: %s\n", argv[1], strerror(errno));
	}
	return -1;
}



