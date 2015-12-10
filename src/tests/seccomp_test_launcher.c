#define _BSD_SOURCE
#include <stdio.h>
#include <string.h>
#include <linux/unistd.h>
#include <linux/audit.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "../misc.h"

char g_cwd[4096];
char g_prog_path[4096];
/* Basic bash syscalls */
int syscalls[] = 
{
	__NR_read,
	__NR_write,
	__NR_time,
	__NR_gettimeofday,
	__NR_open,
	__NR_close,
	__NR_getdents64,
	__NR_getcwd,
	__NR__llseek,
	__NR_fstat64,
	__NR_stat64,
	__NR_lstat64,
	__NR_mmap2,
	__NR_mmap,
	__NR_access,
	__NR_munmap,
	__NR_mprotect,
	__NR_getpid,
	__NR_getppid,
	__NR_getpgrp,
	__NR_getuid32,
	__NR_getgid32,
	__NR_geteuid32,
	__NR_getegid32,	
	__NR_rt_sigprocmask,
	__NR_rt_sigaction,
	__NR_ioctl,
	__NR_fcntl64,
	__NR_dup,
	__NR_dup2,
	__NR_ugetrlimit,
	__NR_getrlimit,
	__NR_clone,
	__NR_nanosleep,
	__NR_setpgid,

	/* for bash to do anything useful.. */
	__NR_readlink,
	/*__NR_execve,*/
	__NR_pipe,
	__NR_pipe2,
	__NR_waitpid,
	__NR_sigreturn,
	__NR_openat,

	/* there is no x32 socket / connect 
	 * this is used for job control i believe?
	 * */
	__NR_socketcall,
	__NR_set_thread_area,
	__NR_brk,
	__NR_uname,
	__NR_exit,
	__NR_exit_group,
};


void fork_and_exec()
{
	pid_t p;
	int status;

	printf("fork_and_exec()\n");
	p = fork();
	if (p == 0)
	{
		char *env[] = { NULL };
		char *arg[] = { "seccomp_test", "2", NULL }; /* print and exit (should fail) */

		if (execve(g_prog_path, arg, env) == -1) {
			printf("execve error on 2'nd exec: %s\n", strerror(errno));
			printf("test passed\n");
		}
		exit(1);
	}
	else if (p == -1){
		printf("fork fail.\n");
		exit(-1);
	}
	if (waitpid(p, &status, 0) == -1) {
		printf("waitpid: %s\n", strerror(errno));
		abort();
	}
	if (WIFEXITED(status))
		printf("exited, status=%d\n", WEXITSTATUS(status));
	else if (WIFSIGNALED(status))
		printf("killed by signal %d\n", WTERMSIG(status));
	else
		printf("test failed?\n");
	
	exit(0);
}


int main(int argc, char *argv[])
{
	static char *arg[] = {
		/* 
		 * XXX for running bash we don't supply args*/
		 "launch_anew",
		 "1",
		 
		NULL
	};
	static char *env[] = {
		"PATH=/sbin:/usr/sbin:/bin:/usr/bin:/usr/local/bin",
		"SHELL=/bin/bash",
		"TERM=linux",
		NULL
	};

	printf("main(argc: %d)\n", argc);
	/* bleh */
	memset(g_prog_path, 0, sizeof(g_prog_path));
	if (getcwd(g_cwd, sizeof(g_cwd)-32) == NULL)
		abort();
	/*snprintf(g_prog_path, sizeof(g_prog_path)-1, "/bin/bash");*/
	snprintf(g_prog_path, sizeof(g_prog_path)-1, "%s/seccomp_test_launcher", g_cwd);
	
	if (argc > 1 && *argv[1] == '1') { /* run fork/exec code path */
		fork_and_exec();
	}
	else if (argc > 1 && *argv[1] == '2') { /* just print and exit */
		printf("if you see this,  TEST FAILED!\n");
		printf("patch kernel with SECCOMP_MODE_FILTER_DEFERRED\n");
		abort();
	}
	else if (argc > 1) {
		printf("invalid args\n");
		abort();
	}


	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
		printf("prctl(): %s\n", strerror(errno));
		abort();
	}
	
	printf("applying seccomp filter\n");
	if (filter_syscalls(AUDIT_ARCH_I386, syscalls, /*XXX nokill=0 verify correct */
			       	sizeof(syscalls) / sizeof(int), 0)) {
		printf("unable to apply syscall filter");
		return -1;
	}

	/*
	 * now we exec bash, it should only work if seccomp is in defer mode
	 * or if the filter has exec whitelisted
	 */
	if (execve(g_prog_path, arg, env) == -1) {
		printf("execve error: %s\n", strerror(errno));
		printf("make sure your cwd(%s) is the directory containing seccomp_test_launcher\n",
				g_prog_path);
		return -1;
	}
	return -99;
}
