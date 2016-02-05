/* (c) Michael R. Tirado -- GPLv3 -- Gnu General Public License version 3
 *
 * ptrace thread that looks for SECCOMP_RET_TRAP filter returns via SIGSYS
 *
 * TODO - This uses SECCOMP_RET_DATA to identify bad systemcalls.
 * 	  Our seccomp filter will have to block future seccomp filters from
 * 	  being installed, as they would be able to send false signals back
 * 	  to us. this could be avoided by doing strace style detection, but
 * 	  could end up being a terrible arch-specific #define mess.
 *
 * TODO - there is a new SECCOMP_RET coming soon that should remove our
 * 	  need to stop on system call entry/exit. and should be faster
 * 	  add option to support this when it is pulled, SECCOMP_RET_ACK
 * 	  is the working title of patch. though we should keep the slower code
 * 	  for argument inspection, and whatnot.
 */

#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/reg.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <linux/ptrace.h>
#include <signal.h>
#include <stdio.h>
#include <stdint.h>
#include <fcntl.h>
#include "seccomp_helper.h"

/* XXX what is the proper way to include this? */
#ifndef SYS_SECCOMP
	#define SYS_SECCOMP 1
#endif

/* TODO test 64bit mode
 * add support for other arch's
 */
#ifdef __x86_64__
	#error notice: x86_64 is untested
	#define REG_CALLNUM (8 * ORIG_RAX)
	#define REG_RETVAL  (8 * RAX)
#else
	#define REG_CALLNUM (4 * ORIG_EAX)
	#define REG_RETVAL  (4 * EAX)
#endif
extern char **environ;

/*
 * 64bit counter for pedantic C89 compilers. 32bit may not be enough to
 * properly sort with if trace left running for extensive periods.
 */
struct sc_info
{
	unsigned long counter[2]; /* enters / exits */
	unsigned long sigsys[2];  /* seccomp_ret_trap's * 2 */
	long callnum;
};

static void sc_init(struct sc_info *sc, unsigned int count)
{
	unsigned int i;
	memset(sc, 0, sizeof(*sc) * count);
	for (i = 0; i < count; ++i) {
		sc[i].callnum = i;
	}
}

static int sc_incr(unsigned long *counter)
{
	if (++counter[0] == 0) {
		if (++counter[1] == 0) {
			counter[0] = 0xffffffff;
			counter[1] = 0xffffffff;
			return -1;
		}
	}
	return 0;
}

static int sc_cmplt(struct sc_info *lhs, struct sc_info *rhs)
{
	if (lhs->counter[1] == rhs->counter[1])
		return (lhs->counter[0] < rhs->counter[0]);
	else
		return (lhs->counter[1] < rhs->counter[1]);
}

/*
 * prints systemcall stats sorted by frequency
 * also generates a configuration file ./podtemplate.pod
 */
void print_stats(struct sc_info *info, unsigned int numbers)
{
	unsigned int i, z;
	struct sc_info tmp;
	int fd;
	int fstatus = 0;

	for (i = 0; i < numbers; ++i)
	{
		/* only one seccomp filter installed, so this should not happen */
		if (info[i].sigsys[1] > 0 || info[i].sigsys[0] > 0) {
			if (info[i].counter[1] > 0 || info[i].counter[0] > 0) {
				printf("sigsys/counter error(%d). exiting.\r\n", i);
				_exit(-1);
			}
			info[i].counter[0] = info[i].sigsys[0];
			info[i].counter[1] = info[i].sigsys[1];
		}
		else if (info[i].counter[1] == 0 && info[i].counter[0] == 0) {
			info[i].callnum = -1; /* flag as not counted */
		}
	}

	/* sort high to low */
	for (i = 0; i < numbers-1; ++i)
	{
		for (z = 0; z < numbers - i - 1; ++z)
		{
			if (sc_cmplt(&info[z], &info[z+1])) {
				memcpy(&tmp, &info[z], sizeof(tmp));
				memcpy(&info[z], &info[z+1], sizeof(tmp));
				memcpy(&info[z+1], &tmp, sizeof(tmp));
			}
		}
	}

	fd = open("podtemplate.pod", O_CREAT|O_TRUNC|O_RDWR, S_IRWXU);
	if (fd == -1) {
		printf("error creating template.pod: %s\r\n", strerror(errno));
		fstatus = -errno;
	}
	printf("\r\n");
	printf("---------  system call frequency ---------\r\n");
	for (i = 0; i < numbers; ++i)
	{
		if (info[i].callnum == -1)
			continue;

		if (info[i].sigsys[0] != 0 || info[i].sigsys[1] != 0)
			printf(" *BLOCKED* ");

		printf("[%lu:%lu] %s\r\n", info[i].counter[1], info[i].counter[0],
				syscall_getname(info[i].callnum));

		/* write line to file */
		if (fstatus >= 0) {
			char buf[256];
			snprintf(buf, 256, "seccomp_allow %s\n",
					syscall_getname(info[i].callnum));
			if (write(fd, buf, strnlen(buf,256)) == -1) {
				printf("write: %s\n", strerror(errno));
				fstatus = -errno;
			}
		}
	}

	close(fd);
	if (fstatus < 0) {
		printf("error occured writing file: %s\n", strerror(-fstatus));
		return;
	}

	printf("\r\n");
	printf("A pod configuration file has been saved as podtemplate.pod\r\n");
	printf("\r\n");
	printf("Some names may be wrong. Below is a list of new systemcalls\r\n");
	printf("that have been added to x86 at least, for finer grained seccomp.\r\n");
	printf("There could be others, Let me know if you come across any more\r\n");
	printf("\r\n");
	printf("\r\n");
	printf("----------------------------------------------------\r\n");
	printf(" __NR_socketcall                        kernel (4.3)\r\n");
	printf("----------------------------------------------------\r\n");
	printf("      __NR_socket\r\n");
	printf("      __NR_socketpair\r\n");
	printf("      __NR_connect\r\n");
	printf("      __NR_accept4\r\n");
	printf("      __NR_bind\r\n");
	printf("      __NR_sendto\r\n");
	printf("      __NR_sendmsg\r\n");
	printf("      __NR_recvfrom\r\n");
	printf("      __NR_recvmsg\r\n");
	printf("      __NR_send\r\n");
	printf("      __NR_recv\r\n");
	printf("      __NR_getpeername\r\n");
	printf("      __NR_getsockname\r\n");
	printf("      __NR_getsockopt\r\n");
	printf("      __NR_setsockopt\r\n");
	printf("      __NR_shutdown\r\n");
	printf("\r\n");
	printf("----------------------------------------------------\r\n");
	printf(" __NR_ipc *not available yet  as of     kernel (4.3)\r\n");
	printf("----------------------------------------------------\r\n");
	/*printf("      __NR_shmget\r\n");
	printf("      __NR_shmat\r\n");
	printf("      __NR_shmdt\r\n");
	printf("      __NR_shmctl\r\n");
	printf("      __NR_msgget\r\n");
	printf("      __NR_msgctl\r\n");
	printf("      __NR_msgrcv\r\n");
	printf("      __NR_msgsnd\r\n");
	printf("      __NR_semget\r\n");
	printf("      __NR_semctl\r\n");
	printf("      __NR_semtimedop\r\n");
	*/
	printf("\r\n");

	/* TODO */
	/*printf("TODO: seccomp_disable option to always return ENOSYS for a call\r\n");
	printf("useful for blocking dangerous calls programs make without killing\r\n");
	printf("while still preserving RET_KILL behavior for unexpected calls\r\n");
	printf("\r\n");*/

}

int tracecalls(pid_t p, int ipc)
{
    int status;
    int ret;
    pid_t curpid;
    long sigsend;
    long numbers;
    struct sc_info *info = NULL;
    unsigned long unknown[2];


    /* +1 to get count of 0 based syscall numbers */
    numbers = syscall_gethighest() + 1;
    info = malloc(numbers * sizeof(struct sc_info));
    if (info == NULL || numbers == 0)
	    _exit(-1);
    memset(info, 0, numbers * sizeof(struct sc_info));
    unknown[0] = 0;
    unknown[1] = 0;
    sc_init(info, numbers);
    status = 0;
    while(1)
    {
	    ret = ptrace(PTRACE_SEIZE, p, NULL,
				      PTRACE_O_TRACECLONE
				     |PTRACE_O_TRACEVFORK
				     |PTRACE_O_TRACEFORK
				     |PTRACE_O_EXITKILL
				     |PTRACE_O_TRACESYSGOOD
				     |PTRACE_O_TRACEEXEC);
	    if (ret == -1 && errno != EPERM) {
		    printf("ptrace_seize: %s\r\n", strerror(errno));
		    _exit(-1);
	    }
	    else if (ret == 0) {
		    break;
	    }
	    /* ptrace will cause EPERM until exec is called, this is due to
	     * setuid transition.  fail after 10 seconds.
	     */
	    if (++status > 100000) {
		    printf("unable to attach to pid: %d\r\n", p);
		    _exit(-1);
	    }
	    usleep(100);
    }
    /* tell jettison_tracee to begin execution */
    while (1)
    {
	const char msg = 'K';
    	if (write(ipc, &msg, 1) == -1) {
		if (errno != EINTR ) {
			printf("tracecalls ipc write: %s\n", strerror(errno));
			_exit(-1);
		}
	}
	else {
		break;
	}
    }
    close(ipc);

    while (1)
    {
	status = 0;
	sigsend = 0;
	curpid = waitpid(-1, &status, __WALL);
	if (curpid == -1) {
		printf("waitpid: %s\r\n", strerror(errno));
		print_stats(info, numbers);
		_exit(-1);
	}
	if ((WIFEXITED(status) || WIFSIGNALED(status))) {
		if (curpid == p) {
			printf("\r\n\r\n");
			printf("[%lu:%lu] unknown system calls made\r\n",
					unknown[1], unknown[0]);
			print_stats(info, numbers);
			_exit(0);
		}
	}
	else if (WIFSTOPPED(status)) {
		if (WSTOPSIG(status) == SIGSYS) {

			siginfo_t sig;

			ret = ptrace(PTRACE_GETSIGINFO, curpid, NULL, &sig);
			if (ret == -1) {
				printf("ptrace_getsiginfo: %s\r\n", strerror(errno));
				print_stats(info, numbers);
				_exit(-1);
			}
			if (sig.si_code == SYS_SECCOMP) {
				long setret = -ENOSYS;
				char *name;
				/*seccomp denied a system call */
				if (sig.si_errno == SECCRET_DENIED) {
					printf("[%d] blacklisted system call -", curpid);
				}
				else {
					printf("[%d] unknown seccomp trap data %d -",
							curpid, sig.si_errno);
				}
				name = syscall_getname(sig.si_syscall);
				if (name) {
					printf("%s\r\n", name);
					/* increment twice to count as enter/exit
					 * display frequency as if it had been accepted
					 */
					sc_incr(info[sig.si_syscall].sigsys);
					sc_incr(info[sig.si_syscall].sigsys);
				}
				else {
					printf("unknown [%d]\r\n", sig.si_syscall);
					sc_incr(unknown);
				}
				ret = ptrace(PTRACE_POKEUSER, curpid, REG_RETVAL,setret);
				if (ret == -1) {
					printf("ptrace_pokeuser:%s\r\n",strerror(errno));
					print_stats(info, numbers);
					_exit(-1);
				}
			}
		}
		else if (WSTOPSIG(status) != (SIGTRAP|0x80)) {
			/* not a syscall stop */
			sigsend = WSTOPSIG(status);
			if (sigsend == SIGTRAP)
				sigsend = 0;
			/*printf("[%d]signal stop(%li)\r\n", curpid, sigsend);*/
		}
	}

	if (status>>8 == (SIGTRAP|0x80)){
		long callnum;

		sigsend = 0;
		errno = 0;
		callnum  = ptrace(PTRACE_PEEKUSER, curpid, REG_CALLNUM, NULL);
		/*printf("[%d] - callnum: %li\r\n", getpid(), callnum);*/
		if (callnum == -1 && errno == 0) {
		}
		else if (callnum == -1) {
			printf("ptrace_peekuser: %s\r\n", strerror(errno));
		}
		else if (callnum < numbers) {
			sc_incr(info[callnum].counter);
		}
		else {
			printf("\r\nunknown syscall: %li\n", callnum);
			sc_incr(unknown);
		}
	}
	else if (status >> 8 == (SIGTRAP|(PTRACE_EVENT_SECCOMP<<8))) {
		printf("\r\nSECCOMP_RET_TRACE: %d\r\n", curpid);
	}
	else if (status >> 8 == (SIGTRAP|(PTRACE_EVENT_EXEC<<8))) {
		/*printf("EXEC STOP: %d\r\n", curpid);*/
	}
	else if (status >> 8 == (SIGTRAP|(PTRACE_EVENT_STOP<<8))) {
		/*printf("EVENT STOP\r\n");*/
	}

	/* resume execution */
	if (ptrace(PTRACE_SYSCALL, curpid, NULL, sigsend) == -1) {
		/*printf("ptrace_cont2(%d): %s\n", curpid, strerror(errno));*/
	}
    }
    return -1;
}

/* build standalone program with -DMAINFUNC cflag */
#ifdef MAINFUNC
/* argv[1] should be pid to trace */
int main(int argc, char *argv[])
{
	long pid;
	int errno;
	char *err;
	if (argc < 2) {
		printf("missing pid argument\n");
		return -1;
	}

	errno = 0;
	pid = strtol(argv[1], &err, 10);
	if (*err || errno) {
		printf("allow_cap not an integer\n");
		return -1;
	}
	if (pid < 1) {
		printf("bad argument\n");
		return -1;
	}
	printf("tracing: %li\n", pid);
	return tracecalls(pid);
}
#endif
