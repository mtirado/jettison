#ifndef SECCOMP_HELPER_H__
#define SECCOMP_HELPER_H__

#define MAX_SYSCALL_DEFLEN 64
#define MAX_SYSCALLS 248 /* maximum number of seccomp'd syscalls we can allow.
			  * for kernels without SECCOMP_MODE_FILTER_DEFERRED
			  * patch we must add execve to every whitelist
			  */

int clear_caps();
int print_caps();
int downgrade_caps(char fcaps[64]);


unsigned int num_syscalls(int *syscalls, unsigned int count);

/*
 * builds a seccomp whitelist filter program for arch specified.
 * syscalls should be an array that holds (count) syscall numbers
 * berkley packet filter program.
 *
 * arch:  ex: AUDIT_ARCH_I386, etc.
 */
int filter_syscalls(int arch, int *syscalls, unsigned int count, long retaction);

/* defstring should be the syscalls #define name,
 * ex: __NR_fork
 * returns the value of the define, or -1 on error
 */
int syscall_helper(char *defstring);

/* returns pointer to a string name of that system call
 * NULL if not recognized.
 */
char *syscall_getname(long syscall_nr);

/* print every time process or ancestors make systemcall not permitted on whitelist */
int seccomp_run_trace(pid_t p);


#endif
