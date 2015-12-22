/* (c) Michael R. Tirado -- GPLv3 -- Gnu General Public License version 3
 *
 * launch program passed in as argv[1] after we receive SIGCONT(18 on linux).
 *
 * usage example:
 *
 *	send SIGCONT 1 second after strace is executed
 *	$(sleep 1 && kill -s 18 <pid>) & strace -p <pid>
 *
 * with jettison the pid you should trace is last process down in T state,
 * then send it a SIGCONT to resume and call exec.
 *
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

extern char **environ;

/* arg[1] should be full program path */
int main(int argc, char *argv[])
{
	pid_t p;
	int status;

	if (argc < 2) {
		printf("missing parameters\n");
		return -1;
	}

	/* pid 1 can't be sent SIGSTOP, so we must fork. this is to ensure
	 * that no systemcalls are missed between when we jettison program
	 * and strace finally attaches to that
	 */
	p = fork();
	if (p == -1)
		return -1;
	if (p == 0) {
		if (kill(getpid(), SIGSTOP)) {
			printf("failed to issue SIGSTOP\n");
			return -1;
		}
		if (execve(argv[1], &argv[1], environ)) {
			printf("exec(%s) error: %s\n", argv[1], strerror(errno));
			return -1;
		}
		return -1;
	}
	else {
		waitpid(p, &status, 0);
	}
	return 0;
}



