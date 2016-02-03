#ifndef SECCOMP_HELPER_H__
#define SECCOMP_HELPER_H__


#define MAX_SYSCALL_DEFLEN 64
#define MAX_SYSCALLS 2000

/* SECCOMP_RET_DATA values,
 * these are only reliable if new process is unable to add
 * additional seccomp filters, through seccomp logic or other means
 */
#define SECCRET_DENIED 0xF0FF




int clear_caps();
int print_caps();
int downgrade_caps(char fcaps[64]);

unsigned int count_syscalls(int *syscalls, unsigned int count);

/*
 * builds a seccomp whitelist filter program for arch specified.
 * syscalls should be an array that holds (count) syscall numbers
 * berkley packet filter program.
 *
 * arch:  ex: AUDIT_ARCH_I386, etc.
 */
int filter_syscalls(int arch, int *syscalls, unsigned int count,
		    int tracing, int blocknew, long retaction);

/* defstring should be the syscalls #define name,
 * ex: "__NR_fork"
 * returns the value of the define, or -1 on error
 */
int syscall_getnum(char *defstring);

/* returns pointer to a string name of that system call
 * NULL if not recognized.
 */
char *syscall_getname(long syscall_nr);

/* return the highest system call number */
unsigned int syscall_gethighest();

/* returns total number of systemcall entries in sc_translate table */
unsigned int syscall_tablesize();

/* print every time process or ancestors make systemcall not permitted on whitelist */
int seccomp_run_trace(pid_t p);


#endif
