/* (c) 2015 Michael R. Tirado -- GPLv3, GNU General Public License, version 3.
 * contact: mtirado418@gmail.com
 */
#ifndef MISC_H__
#define MISC_H__

#define MAX_SYSCALL_DEFLEN 64
#define MAX_SYSCALLS 246 /* for kernels without SECCOMP_MODE_FILTER_DEFERRED patch we
			  * add execve and setreuid + 32 to every whitelist, which is
			  * 3 extra instructions subtracted from limit
			  */


/* chop consecutive matching characters starting at the end of string
 * returns 0 on first non matching character, -1 on error.
 * size is the maximum size the string could be
 */
int chop_trailing(char *string, unsigned int size, const char match);



/* tty/console */
int console_setup();
/* slave path should be an array[MAX_SYSTEMPATH] */
int pty_create(int *fd_master, int master_flags,
	       char outslave_path[MAX_SYSTEMPATH]);
int switch_terminal(char *path, int hangup);



/* logging TODO -- move into eslib... */
void logmsg(char *ident, char *msg, char *info, int option, int facility, int lvl);
void loginfo(const char *fmt, ...);
void logerror(const char *fmt, ...);
void logcrit(const char *fmt, ...);
void logemerg(const char *fmt, ...);



/********  seccomp helper.c *******/
int clear_caps();
int make_uncapable(char fcaps[64]);

unsigned int num_syscalls(int *syscalls, unsigned int count);

/*
 * builds a seccomp whitelist filter program for arch specified.
 * syscalls should be an array that holds (count) syscall numbers
 * berkley packet filter program.
 *
 * arch:  ex: AUDIT_ARCH_I386, etc.
 */
int filter_syscalls(int arch, int *syscalls, unsigned int count, int nokill);

/* defstring should be the syscalls #define name,
 * ex: __NR_fork
 * returns the value of the define, or -1 on error
 */
int syscall_helper(char *defstring);



#endif










