#ifndef SECCOMP_HELPER_H__
#define SECCOMP_HELPER_H__


#include <linux/audit.h>
#include <linux/seccomp.h>

#define MAX_SYSCALL_DEFLEN 64
#define MAX_CAP_DEFLEN 64
#define MAX_SYSCALLS 2000

#define NUM_OF_CAPS 64

/* SECCOMP_RET_DATA values,
 * these are only reliable if new process is unable to install
 * additional seccomp filters using SECCOPT_BLOCKNEW.
 */
#define SECCRET_DENIED 0xF0FF

#define SECCOPT_BLOCKNEW 0x1
#define SECCOPT_PTRACE   0x2

#ifdef __x86_64__ /* TODO this is untested... add other arch's */
	#define SYSCALL_ARCH AUDIT_ARCH_X86_64
#elif __i386__
	#define SYSCALL_ARCH AUDIT_ARCH_I386
#else
	#error arch lacks systemcall define, add it and test!
#endif

int clear_caps();
int print_caps();
int downgrade_caps();
int capbset_drop(int fcaps[NUM_OF_CAPS]);
int jail_process(char *chroot_path,
		 uid_t set_reuid, /* if these are 0, no setreuid call is made */
		 gid_t set_regid,
		 int  *whitelist,
		 unsigned long seccomp_opts,
		 int cap_e[NUM_OF_CAPS],
		 int cap_p[NUM_OF_CAPS],
		 int cap_i[NUM_OF_CAPS],
		 int can_write,
		 int can_exec);

unsigned int count_syscalls(int *syscalls, unsigned int count);

/*
 * builds a seccomp whitelist filter program for arch specified.
 * syscalls should be an array that holds (count) syscall numbers
 * berkley packet filter program.
 *
 * arch:  ex: AUDIT_ARCH_I386, etc.
 */
int filter_syscalls(int arch, int *whitelist, int *blocklist,
		    unsigned int wcount, unsigned int bcount,
		    unsigned int options, long retaction);

/* defstring should be the syscalls #define name,
 * ex: "__NR_fork"
 * returns the value of the define, or -1 on error
 */
int syscall_getnum(char *defstring);

/* returns pointer to a string name of that system call
 * NULL if not recognized.
 */
char *syscall_getname(long syscall_nr);

/* print systemcalls that we know about */
void syscall_printknown();

/* return the highest system call number */
unsigned int syscall_gethighest();

/* returns total number of systemcall entries in sc_translate table */
unsigned int syscall_tablesize();

/*
 * return value of capability, defined in <linux/capability.h>
 * -1/NULL is an error
 */
int cap_getnum(char *defstring);
char *cap_getname(int cap_nr);



#endif
