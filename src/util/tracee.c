/* (c) Michael R. Tirado -- GPLv3 -- Gnu General Public License version 3
 *
 * pid 1 cannot be ptraced. we must fork
 *
 * launch program passed in as argv[1] after we receive ipc go-ahead.
 *
 * usage: ipc socket is a socketpair used to translate pid's between namespaces
 * 	  as well as implement a stop before calling exec.
 * 	  this is intended to be forked with ipc fdnum at end of process name
 * 	  in order to preserve arguments that need to be passed to program.
 * 	  set the name to trace7 for example, in argv[0] before exec
 * 	  and make sure socket does not have O_CLOEXEC set.
 *
 * 	  TODO test with yama mode 1, might need some modification
 *
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
	pid_t p, traceepid;
	int status, ipc;
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



	p = fork();
	if (p == -1)
		return -1;
	if (p == 0) {
		if (ipc != -1) {
			if (eslib_sock_send_cred(ipc)) {
				printf("unable to translate pid number\n");
				return -1;
			}
			/* wait for ack over ipc before execution */
			while(1)
			{
				int r;
				char buf = 0;
				printf("reading\n");
				r = read(ipc, &buf, 1);
				if (r == -1) {
					if (errno == EINTR) {
						continue;
					}
					printf("trace ipc error: %s\n",	strerror(errno));
					return -1;
				}
				else if (buf == 'K') {
					break;
				}
				else {
					printf("bad ipc msg\n");
					return -1;
				}
			}
			close(ipc);

		}
		else {
			/* no ipc, issue sigstop until tracer continues */
			if (kill(getpid(), SIGSTOP))
				return -1;
		}

		printf("tracee exec\n");
		if (execve(argv[1], &argv[1], environ)) {
			printf("exec(%s) error: %s\n", argv[1], strerror(errno));
			return -1;
		}
	}

	close(ipc);
	traceepid = p;
	while(1)
	{
		p = waitpid(traceepid, &status, 0);
		if (p == traceepid) {
			return 0;
		}
		else if (p == -1 && errno != EINTR) {
			printf("tracee waitpid: %d\n", status);
			return -1;
		}
	}
	return -1;
}



