/* (c) 2015 Michael R. Tirado -- GPLv3, GNU General Public License, version 3.
 * contact: mtirado418@gmail.com
 *
 * helper functions for seccomp filter creation, and capability drop.
 */

#define _GNU_SOURCE
#include <linux/capability.h>
#include <linux/securebits.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/unistd.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <malloc.h>
#include <memory.h>
#include <errno.h>
#include "../misc.h"


#ifndef SECCOMP_MODE_FILTER_DEFERRED
#define SECCOMP_MODE_FILTER_DEFERRED (-1)
#endif


/* translate config file strings to syscall number */
struct sc_translate
{
	char defname[MAX_SYSCALL_DEFLEN];
	int  nr;
};


/* XXX
 * there may be system calls missing if you're on a newer kernel.
 * if on an older kernel, you may need to comment out some syscalls.
 *
 * version: 4.2
 */
struct sc_translate sc_table[] = {
/*{ "__NR_restart_syscall", __NR_restart_syscall },*/
{ "__NR_exit", __NR_exit },
{ "__NR_fork", __NR_fork },
{ "__NR_read", __NR_read },
{ "__NR_write", __NR_write },
{ "__NR_open", __NR_open },
{ "__NR_close", __NR_close },
{ "__NR_waitpid", __NR_waitpid },
{ "__NR_creat", __NR_creat },
{ "__NR_link", __NR_link },
{ "__NR_unlink", __NR_unlink },
{ "__NR_execve", __NR_execve },
{ "__NR_chdir", __NR_chdir },
{ "__NR_time", __NR_time },
{ "__NR_mknod", __NR_mknod },
{ "__NR_chmod", __NR_chmod },
{ "__NR_lchown", __NR_lchown },
{ "__NR_break", __NR_break },
{ "__NR_oldstat", __NR_oldstat },
{ "__NR_lseek", __NR_lseek },
{ "__NR_getpid", __NR_getpid },
{ "__NR_mount", __NR_mount },
{ "__NR_umount", __NR_umount },
{ "__NR_setuid", __NR_setuid },
{ "__NR_getuid", __NR_getuid },
{ "__NR_stime", __NR_stime },
{ "__NR_ptrace", __NR_ptrace },
{ "__NR_alarm", __NR_alarm },
{ "__NR_oldfstat", __NR_oldfstat },
{ "__NR_pause", __NR_pause },
{ "__NR_utime", __NR_utime },
{ "__NR_stty", __NR_stty },
{ "__NR_gtty", __NR_gtty },
{ "__NR_access", __NR_access },
{ "__NR_nice", __NR_nice },
{ "__NR_ftime", __NR_ftime },
{ "__NR_sync", __NR_sync },
{ "__NR_kill", __NR_kill },
{ "__NR_rename", __NR_rename },
{ "__NR_mkdir", __NR_mkdir },
{ "__NR_rmdir", __NR_rmdir },
{ "__NR_dup", __NR_dup },
{ "__NR_pipe", __NR_pipe },
{ "__NR_times", __NR_times },
{ "__NR_prof", __NR_prof },
{ "__NR_brk", __NR_brk },
{ "__NR_setgid", __NR_setgid },
{ "__NR_getgid", __NR_getgid },
{ "__NR_signal", __NR_signal },
{ "__NR_geteuid", __NR_geteuid },
{ "__NR_getegid", __NR_getegid },
{ "__NR_acct", __NR_acct },
{ "__NR_umount2", __NR_umount2 },
{ "__NR_lock", __NR_lock },
{ "__NR_ioctl", __NR_ioctl },
{ "__NR_fcntl", __NR_fcntl },
{ "__NR_mpx", __NR_mpx },
{ "__NR_setpgid", __NR_setpgid },
{ "__NR_ulimit", __NR_ulimit },
{ "__NR_oldolduname", __NR_oldolduname },
{ "__NR_umask", __NR_umask },
{ "__NR_chroot", __NR_chroot },
{ "__NR_ustat", __NR_ustat },
{ "__NR_dup2", __NR_dup2 },
{ "__NR_getppid", __NR_getppid },
{ "__NR_getpgrp", __NR_getpgrp },
{ "__NR_setsid", __NR_setsid },
{ "__NR_sigaction", __NR_sigaction },
{ "__NR_sgetmask", __NR_sgetmask },
{ "__NR_ssetmask", __NR_ssetmask },
{ "__NR_setreuid", __NR_setreuid },
{ "__NR_setregid", __NR_setregid },
{ "__NR_sigsuspend", __NR_sigsuspend },
{ "__NR_sigpending", __NR_sigpending },
{ "__NR_sethostname", __NR_sethostname },
{ "__NR_setrlimit", __NR_setrlimit },
{ "__NR_getrlimit", __NR_getrlimit },
{ "__NR_getrusage", __NR_getrusage },
{ "__NR_gettimeofday", __NR_gettimeofday },
{ "__NR_settimeofday", __NR_settimeofday },
{ "__NR_getgroups", __NR_getgroups },
{ "__NR_setgroups", __NR_setgroups },
{ "__NR_select", __NR_select },
{ "__NR_symlink", __NR_symlink },
{ "__NR_oldlstat", __NR_oldlstat },
{ "__NR_readlink", __NR_readlink },
{ "__NR_uselib", __NR_uselib },
{ "__NR_swapon", __NR_swapon },
{ "__NR_reboot", __NR_reboot },
{ "__NR_readdir", __NR_readdir },
{ "__NR_mmap", __NR_mmap },
{ "__NR_munmap", __NR_munmap },
{ "__NR_truncate", __NR_truncate },
{ "__NR_ftruncate", __NR_ftruncate },
{ "__NR_fchmod", __NR_fchmod },
{ "__NR_fchown", __NR_fchown },
{ "__NR_getpriority", __NR_getpriority },
{ "__NR_setpriority", __NR_setpriority },
{ "__NR_profil", __NR_profil },
{ "__NR_statfs", __NR_statfs },
{ "__NR_fstatfs", __NR_fstatfs },
{ "__NR_ioperm", __NR_ioperm },
{ "__NR_socketcall", __NR_socketcall },
{ "__NR_syslog", __NR_syslog },
{ "__NR_setitimer", __NR_setitimer },
{ "__NR_getitimer", __NR_getitimer },
{ "__NR_stat", __NR_stat },
{ "__NR_lstat", __NR_lstat },
{ "__NR_fstat", __NR_fstat },
{ "__NR_olduname", __NR_olduname },
{ "__NR_iopl", __NR_iopl },
{ "__NR_vhangup", __NR_vhangup },
{ "__NR_idle", __NR_idle },
{ "__NR_vm86old", __NR_vm86old },
{ "__NR_wait4", __NR_wait4 },
{ "__NR_swapoff", __NR_swapoff },
{ "__NR_sysinfo", __NR_sysinfo },
{ "__NR_ipc", __NR_ipc },
{ "__NR_fsync", __NR_fsync },
{ "__NR_sigreturn", __NR_sigreturn },
{ "__NR_clone", __NR_clone },
{ "__NR_setdomainname", __NR_setdomainname },
{ "__NR_uname", __NR_uname },
{ "__NR_modify_ldt", __NR_modify_ldt },
{ "__NR_adjtimex", __NR_adjtimex },
{ "__NR_mprotect", __NR_mprotect },
{ "__NR_sigprocmask", __NR_sigprocmask },
{ "__NR_create_module", __NR_create_module },
{ "__NR_init_module", __NR_init_module },
{ "__NR_delete_module", __NR_delete_module },
{ "__NR_get_kernel_syms", __NR_get_kernel_syms },
{ "__NR_quotactl", __NR_quotactl },
{ "__NR_getpgid", __NR_getpgid },
{ "__NR_fchdir", __NR_fchdir },
{ "__NR_bdflush", __NR_bdflush },
{ "__NR_sysfs", __NR_sysfs },
{ "__NR_personality", __NR_personality },
{ "__NR_afs_syscall", __NR_afs_syscall },
{ "__NR_setfsuid", __NR_setfsuid },
{ "__NR_setfsgid", __NR_setfsgid },
{ "__NR__llseek", __NR__llseek },
{ "__NR_getdents", __NR_getdents },
{ "__NR__newselect", __NR__newselect },
{ "__NR_flock", __NR_flock },
{ "__NR_msync", __NR_msync },
{ "__NR_readv", __NR_readv },
{ "__NR_writev", __NR_writev },
{ "__NR_getsid", __NR_getsid },
{ "__NR_fdatasync", __NR_fdatasync },
{ "__NR__sysctl", __NR__sysctl },
{ "__NR_mlock", __NR_mlock },
{ "__NR_munlock", __NR_munlock },
{ "__NR_mlockall", __NR_mlockall },
{ "__NR_munlockall", __NR_munlockall },
{ "__NR_sched_setparam", __NR_sched_setparam },
{ "__NR_sched_getparam", __NR_sched_getparam },
{ "__NR_sched_setscheduler", __NR_sched_setscheduler },
{ "__NR_sched_getscheduler", __NR_sched_getscheduler },
{ "__NR_sched_yield", __NR_sched_yield },
{ "__NR_sched_get_priority_max", __NR_sched_get_priority_max },
{ "__NR_sched_get_priority_min", __NR_sched_get_priority_min },
{ "__NR_sched_rr_get_interval", __NR_sched_rr_get_interval },
{ "__NR_nanosleep", __NR_nanosleep },
{ "__NR_mremap", __NR_mremap },
{ "__NR_setresuid", __NR_setresuid },
{ "__NR_getresuid", __NR_getresuid },
{ "__NR_vm86", __NR_vm86 },
{ "__NR_query_module", __NR_query_module },
{ "__NR_poll", __NR_poll },
{ "__NR_nfsservctl", __NR_nfsservctl },
{ "__NR_setresgid", __NR_setresgid },
{ "__NR_getresgid", __NR_getresgid },
{ "__NR_prctl", __NR_prctl },
{ "__NR_rt_sigreturn", __NR_rt_sigreturn },
{ "__NR_rt_sigaction", __NR_rt_sigaction },
{ "__NR_rt_sigprocmask", __NR_rt_sigprocmask },
{ "__NR_rt_sigpending", __NR_rt_sigpending },
{ "__NR_rt_sigtimedwait", __NR_rt_sigtimedwait },
{ "__NR_rt_sigqueueinfo", __NR_rt_sigqueueinfo },
{ "__NR_rt_sigsuspend", __NR_rt_sigsuspend },
{ "__NR_pread64", __NR_pread64 },
{ "__NR_pwrite64", __NR_pwrite64 },
{ "__NR_chown", __NR_chown },
{ "__NR_getcwd", __NR_getcwd },
{ "__NR_capget", __NR_capget },
{ "__NR_capset", __NR_capset },
{ "__NR_sigaltstack", __NR_sigaltstack },
{ "__NR_sendfile", __NR_sendfile },
{ "__NR_getpmsg", __NR_getpmsg },
{ "__NR_putpmsg", __NR_putpmsg },
{ "__NR_vfork", __NR_vfork },
{ "__NR_ugetrlimit", __NR_ugetrlimit },
{ "__NR_mmap2", __NR_mmap2 },
{ "__NR_truncate64", __NR_truncate64 },
{ "__NR_ftruncate64", __NR_ftruncate64 },
{ "__NR_stat64", __NR_stat64 },
{ "__NR_lstat64", __NR_lstat64 },
{ "__NR_fstat64", __NR_fstat64 },
{ "__NR_lchown32", __NR_lchown32 },
{ "__NR_getuid32", __NR_getuid32 },
{ "__NR_getgid32", __NR_getgid32 },
{ "__NR_geteuid32", __NR_geteuid32 },
{ "__NR_getegid32", __NR_getegid32 },
{ "__NR_setreuid32", __NR_setreuid32 },
{ "__NR_setregid32", __NR_setregid32 },
{ "__NR_getgroups32", __NR_getgroups32 },
{ "__NR_setgroups32", __NR_setgroups32 },
{ "__NR_fchown32", __NR_fchown32 },
{ "__NR_setresuid32", __NR_setresuid32 },
{ "__NR_getresuid32", __NR_getresuid32 },
{ "__NR_setresgid32", __NR_setresgid32 },
{ "__NR_getresgid32", __NR_getresgid32 },
{ "__NR_chown32", __NR_chown32 },
{ "__NR_setuid32", __NR_setuid32 },
{ "__NR_setgid32", __NR_setgid32 },
{ "__NR_setfsuid32", __NR_setfsuid32 },
{ "__NR_setfsgid32", __NR_setfsgid32 },
{ "__NR_pivot_root", __NR_pivot_root },
{ "__NR_mincore", __NR_mincore },
{ "__NR_madvise", __NR_madvise },
{ "__NR_getdents64", __NR_getdents64 },
{ "__NR_fcntl64", __NR_fcntl64 },
{ "__NR_gettid", __NR_gettid },
{ "__NR_readahead", __NR_readahead },
{ "__NR_setxattr", __NR_setxattr },
{ "__NR_lsetxattr", __NR_lsetxattr },
{ "__NR_fsetxattr", __NR_fsetxattr },
{ "__NR_getxattr", __NR_getxattr },
{ "__NR_lgetxattr", __NR_lgetxattr },
{ "__NR_fgetxattr", __NR_fgetxattr },
{ "__NR_listxattr", __NR_listxattr },
{ "__NR_llistxattr", __NR_llistxattr },
{ "__NR_flistxattr", __NR_flistxattr },
{ "__NR_removexattr", __NR_removexattr },
{ "__NR_lremovexattr", __NR_lremovexattr },
{ "__NR_fremovexattr", __NR_fremovexattr },
{ "__NR_tkill", __NR_tkill },
{ "__NR_sendfile64", __NR_sendfile64 },
{ "__NR_futex", __NR_futex },
{ "__NR_sched_setaffinity", __NR_sched_setaffinity },
{ "__NR_sched_getaffinity", __NR_sched_getaffinity },
{ "__NR_set_thread_area", __NR_set_thread_area },
{ "__NR_get_thread_area", __NR_get_thread_area },
{ "__NR_io_setup", __NR_io_setup },
{ "__NR_io_destroy", __NR_io_destroy },
{ "__NR_io_getevents", __NR_io_getevents },
{ "__NR_io_submit", __NR_io_submit },
{ "__NR_io_cancel", __NR_io_cancel },
{ "__NR_fadvise64", __NR_fadvise64 },
{ "__NR_exit_group", __NR_exit_group },
{ "__NR_lookup_dcookie", __NR_lookup_dcookie },
{ "__NR_epoll_create", __NR_epoll_create },
{ "__NR_epoll_ctl", __NR_epoll_ctl },
{ "__NR_epoll_wait", __NR_epoll_wait },
{ "__NR_remap_file_pages", __NR_remap_file_pages },
{ "__NR_set_tid_address", __NR_set_tid_address },
{ "__NR_timer_create", __NR_timer_create },
{ "__NR_timer_settime", __NR_timer_settime },
{ "__NR_timer_gettime", __NR_timer_gettime },
{ "__NR_timer_getoverrun", __NR_timer_getoverrun },
{ "__NR_timer_delete", __NR_timer_delete },
{ "__NR_clock_settime", __NR_clock_settime },
{ "__NR_clock_gettime", __NR_clock_gettime },
{ "__NR_clock_getres", __NR_clock_getres },
{ "__NR_clock_nanosleep", __NR_clock_nanosleep },
{ "__NR_statfs64", __NR_statfs64 },
{ "__NR_fstatfs64", __NR_fstatfs64 },
{ "__NR_tgkill", __NR_tgkill },
{ "__NR_utimes", __NR_utimes },
{ "__NR_fadvise64_64", __NR_fadvise64_64 },
{ "__NR_vserver", __NR_vserver },
{ "__NR_mbind", __NR_mbind },
{ "__NR_get_mempolicy", __NR_get_mempolicy },
{ "__NR_set_mempolicy", __NR_set_mempolicy },
{ "__NR_mq_open", __NR_mq_open },
{ "__NR_mq_unlink", __NR_mq_unlink },
{ "__NR_mq_timedsend", __NR_mq_timedsend },
{ "__NR_mq_timedreceive", __NR_mq_timedreceive },
{ "__NR_mq_notify", __NR_mq_notify },
{ "__NR_mq_getsetattr", __NR_mq_getsetattr },
{ "__NR_kexec_load", __NR_kexec_load },
{ "__NR_waitid", __NR_waitid },
{ "__NR_add_key", __NR_add_key },
{ "__NR_request_key", __NR_request_key },
{ "__NR_keyctl", __NR_keyctl },
{ "__NR_ioprio_set", __NR_ioprio_set },
{ "__NR_ioprio_get", __NR_ioprio_get },
{ "__NR_inotify_init", __NR_inotify_init },
{ "__NR_inotify_add_watch", __NR_inotify_add_watch },
{ "__NR_inotify_rm_watch", __NR_inotify_rm_watch },
{ "__NR_migrate_pages", __NR_migrate_pages },
{ "__NR_openat", __NR_openat },
{ "__NR_mkdirat", __NR_mkdirat },
{ "__NR_mknodat", __NR_mknodat },
{ "__NR_fchownat", __NR_fchownat },
{ "__NR_futimesat", __NR_futimesat },
{ "__NR_fstatat64", __NR_fstatat64 },
{ "__NR_unlinkat", __NR_unlinkat },
{ "__NR_renameat", __NR_renameat },
{ "__NR_linkat", __NR_linkat },
{ "__NR_symlinkat", __NR_symlinkat },
{ "__NR_readlinkat", __NR_readlinkat },
{ "__NR_fchmodat", __NR_fchmodat },
{ "__NR_faccessat", __NR_faccessat },
{ "__NR_pselect6", __NR_pselect6 },
{ "__NR_ppoll", __NR_ppoll },
{ "__NR_unshare", __NR_unshare },
{ "__NR_set_robust_list", __NR_set_robust_list },
{ "__NR_get_robust_list", __NR_get_robust_list },
{ "__NR_splice", __NR_splice },
{ "__NR_sync_file_range", __NR_sync_file_range },
{ "__NR_tee", __NR_tee },
{ "__NR_vmsplice", __NR_vmsplice },
{ "__NR_move_pages", __NR_move_pages },
{ "__NR_getcpu", __NR_getcpu },
{ "__NR_epoll_pwait", __NR_epoll_pwait },
{ "__NR_utimensat", __NR_utimensat },
{ "__NR_signalfd", __NR_signalfd },
{ "__NR_timerfd_create", __NR_timerfd_create },
{ "__NR_eventfd", __NR_eventfd },
{ "__NR_fallocate", __NR_fallocate },
{ "__NR_timerfd_settime", __NR_timerfd_settime },
{ "__NR_timerfd_gettime", __NR_timerfd_gettime },
{ "__NR_signalfd4", __NR_signalfd4 },
{ "__NR_eventfd2", __NR_eventfd2 },
{ "__NR_epoll_create1", __NR_epoll_create1 },
{ "__NR_dup3", __NR_dup3 },
{ "__NR_pipe2", __NR_pipe2 },
{ "__NR_inotify_init1", __NR_inotify_init1 },
{ "__NR_preadv", __NR_preadv },
{ "__NR_pwritev", __NR_pwritev },
{ "__NR_rt_tgsigqueueinfo", __NR_rt_tgsigqueueinfo },
{ "__NR_perf_event_open", __NR_perf_event_open },
{ "__NR_recvmmsg", __NR_recvmmsg },
{ "__NR_fanotify_init", __NR_fanotify_init },
{ "__NR_fanotify_mark", __NR_fanotify_mark },
{ "__NR_prlimit64", __NR_prlimit64 },
{ "__NR_name_to_handle_at", __NR_name_to_handle_at },
{ "__NR_open_by_handle_at", __NR_open_by_handle_at },
{ "__NR_clock_adjtime", __NR_clock_adjtime },
{ "__NR_syncfs", __NR_syncfs },
{ "__NR_sendmmsg", __NR_sendmmsg },
{ "__NR_setns", __NR_setns },
{ "__NR_process_vm_readv", __NR_process_vm_readv },
{ "__NR_process_vm_writev", __NR_process_vm_writev },
{ "__NR_kcmp", __NR_kcmp },
{ "__NR_finit_module", __NR_finit_module },

/*
{ "__NR_sched_setattr", __NR_sched_setattr },
{ "__NR_sched_getattr", __NR_sched_getattr },
{ "__NR_renameat2", __NR_renameat2 },
{ "__NR_seccomp", __NR_seccomp },
{ "__NR_getrandom", __NR_getrandom },
{ "__NR_memfd_create", __NR_memfd_create },
{ "__NR_bpf", __NR_bpf },
{ "__NR_execveat", __NR_execveat },
*/
};

int syscall_helper(char *defstring)
{
	unsigned int i;
	unsigned int count;
	char buf[MAX_SYSCALL_DEFLEN];

	memset(buf, 0, MAX_SYSCALL_DEFLEN);
	strncpy(buf, defstring, MAX_SYSCALL_DEFLEN-1);

	count = sizeof(sc_table) / sizeof(struct sc_translate);
	for (i = 0; i < count; ++i)
	{
		if (strncmp(buf, sc_table[i].defname, MAX_SYSCALL_DEFLEN) == 0)
			return sc_table[i].nr;
	}
	return -1;
}


unsigned int num_syscalls(int *syscalls, unsigned int count)
{
	unsigned int i;
	for (i = 0; i < count; ++i)
	{
		if (syscalls[i] == -1)
			return i;
	}
	return count;
}

/*
 * TODO?: this only supports 250 or so calls because filter only supports
 * 8 bit jump offsets.  to overcome this will require a bit of extra jump logic.
 * if you need more than 250 whitelisted, you probably want to use a blacklist,
 * otherwise any hopes for high performance may be lost.
 */
#define SECBPF_INSTR(_i, _c, _t, _f, _k)	\
{						\
	_i.code = _c;				\
	_i.jt   = _t;				\
	_i.jf   = _f;				\
	_i.k    = _k;				\
}
#define SECBPF_LD_ABSW(i, k)	SECBPF_INSTR(i, (BPF_LD|BPF_W|BPF_ABS), 0, 0, k)
#define SECBPF_JE(i, k, t, f)	SECBPF_INSTR(i, (BPF_JMP|BPF_JEQ|BPF_K), t, f, k)
#define SECBPF_RET(i, k)	SECBPF_INSTR(i, (BPF_RET|BPF_K), 0, 0, k)
#define SECDAT_ARCH		offsetof(struct seccomp_data, arch)
#define SECDAT_NR		offsetof(struct seccomp_data, nr)


struct sock_filter *build_seccomp_whitelist(int arch, int *syscalls,
		unsigned int count, unsigned int *instr_count, int ughlyhack, int nokill)
{
	unsigned int i;
	unsigned int proglen = 5 + count;
	/* jumping to [2] will execute [3], so these are 1 less than you'd think */
	unsigned int bad  = proglen - 3; /* fail if not found */
	unsigned int good = proglen - 2; /* jumps here if in list */
	struct sock_filter *instructions = NULL;


	if (count > MAX_SYSCALLS) {
		printf("currently we only support %d syscalls in whitelist\n",
			       	MAX_SYSCALLS);
		return NULL;
	}

	/*
	 * UUGGHHHHLY f'n hack to allow users without a seccomp patch to run jettison
	 */
	if (ughlyhack == 1) {
		proglen += 3;
		good += 3;
		bad += 3; /* BAD!! */
	}

	printf("build_whitelist count: %d\n", count);

	instructions = malloc(proglen * sizeof(struct sock_filter));
	if (instructions == NULL)
		return NULL;

	/*
	 *  create seccomp bpf filter
	 */
	memset(instructions, 0, proglen * sizeof(struct sock_filter));

	/* validate arch */
	SECBPF_LD_ABSW(instructions[0], SECDAT_ARCH);
	/* jumps are relative, subtract the index(1) */
	SECBPF_JE(instructions[1], arch, 0, bad - 1);

	/* load syscall number */
	SECBPF_LD_ABSW(instructions[2], SECDAT_NR);

	/* generate jumps for allowed syscalls*/
	for (i = 3; i < count + 3; ++i)
	{
		if (syscalls[i-3] == -1) {
			printf("invalid syscall\n");
			free(instructions);
			return NULL;
		}
		/* jumps to good if equal, make jump 'label' relative */
		SECBPF_JE(instructions[i], syscalls[i-3], good - i, 0);
	}

	/* there really was no other way, :[
	 * add execve and setreuid to whitelist.
	 */
	if (ughlyhack == 1) {
		SECBPF_JE(instructions[i], __NR_setreuid32, good - i, 0);
		++i;
		SECBPF_JE(instructions[i], __NR_setreuid, good - i, 0);
		++i;
		SECBPF_JE(instructions[i], __NR_execve, good - i, 0);
		++i;
	}

	/* bad, kill by default.
	 * use nokill for debugging / finding syscalls to add to whitelist */
	if (nokill) {
		SECBPF_RET(instructions[i],SECCOMP_RET_ERRNO|(ENOSYS & SECCOMP_RET_DATA));
	}
	else {
		SECBPF_RET(instructions[i],SECCOMP_RET_KILL);
	}
	++i;

	/* good, allowed */
	SECBPF_RET(instructions[i], SECCOMP_RET_ALLOW);

	*instr_count = proglen;
	return instructions;
}


/* no deferred hackery in kernel, we have to whitelist setreuid and execve  :( 
 * TODO setreuid can be optional if user has no interest in running
 * programs with file capabilities.
 * */
int filter_syscalls_fallback(int arch, int *syscalls, unsigned int count, int nokill)
{
	struct sock_filter *filter;
	struct sock_fprog prog;
	unsigned int instr_count;

	filter = build_seccomp_whitelist(arch, syscalls, count, &instr_count, 1, nokill);
	if (filter == NULL)
		return -1;

	memset(&prog, 0, sizeof(prog));
	prog.len = instr_count;
	prog.filter = filter;

	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) == -1) {
		printf("error installing seccomp filter: %s\n", strerror(errno));
		free(filter);
		return -1;
	}
	printf("whitelisted %d system calls\n", instr_count);
	printf("filter: %p\n", (void *)filter);
	free(filter);
	return 0;
}


int filter_syscalls(int arch, int *syscalls, unsigned int count, int nokill)
{
	/*struct sock_filter *filter;
	struct sock_fprog prog;
	unsigned int instr_count;

	memset(&prog, 0, sizeof(prog));
	filter = build_seccomp_whitelist(arch, syscalls, count, &instr_count, 0, nokill);
	if (filter == NULL)
		return -1;

	printf("whitelisted %d system calls\n", instr_count);
	printf("filter: %p\n", (void *)filter);
	prog.len = instr_count;
	prog.filter = filter;
	*/
	/* TODO -- check for SECCOMP_FILTER_FLAG_DEFER, use fallback if not found */	
	return filter_syscalls_fallback(arch, syscalls, count, nokill);

	/*free(filter);
	return 0;*/
}


/*
 * drop all caps from thread, unless pod requested them.
 * set capability bounding set to prevent thread from gaining privileges
 * such as MKNOiD, SET_FCAP, SET_PCAP, etc...
 *
 */
extern int capset(cap_user_header_t header, cap_user_data_t data);
extern int capget(cap_user_header_t header, const cap_user_data_t data);

static int capbset_drop(unsigned long cap, char fcaps[64])
{

	if (cap >= 64) {
		printf("cap out of bounds\n");
		return -1;
	}

	/* is pod requesting we allow file cap? */
	if (fcaps[cap]) {
		/*
		 * FILE CAP BLACKLIST
		 * some caps should never be allowed (MKNOD, SYS_MODULE!!)
		 * SYS_ADMIN would allow remounting files to change mount flags,
		 * and possibly exploit privileged programs (LD_PRELOAD style)
		 * you can comment out what you need, i just took the extra
		 * paranoid approach of blocking everything that may cause system
		 * wide security issues in the case of a successful exploit scenario.
		 * if your file cap'd programs have been reviewd and are sufficiently
		 * secure, then you should not worry as much as i have with this list.
		 */
		switch(cap)
		{
		/* XXX if you decide on allowing suid programs, make sure
		 * that we can block MKNOD with bounding set (i'm pretty sure
		 * setuid programs use bounding set but not 100% ) */
		case CAP_MKNOD:
			printf("CAP_MKNOD is prohibited\n");
			break;
		case CAP_SETPCAP:
			printf("CAP_SETPCAP is prohibited\n");
			break;
		case CAP_SETFCAP:
			printf("CAP_SETFCAP is prohibited\n");
			break;
		case CAP_DAC_OVERRIDE:
			printf("CAP_DAC_OVERRIDE is prohibited\n");
			break;
		case CAP_SYS_ADMIN: /* don't allow remounts... */
			printf("CAP_SYS_ADMIN is prohibited\n");
			break;
		/*case CAP_DAC_READ_SEARCH:
			printf("CAP_DAC_READ_SEARCH is prohibited\n");
			break;*/
		case CAP_MAC_OVERRIDE:
			printf("CAP_MAC_OVERRIDE is prohibited\n");
			break;
		case CAP_MAC_ADMIN:
			printf("CAP_MAC_ADMIN is prohibited\n");
			break;
		case CAP_CHOWN:
			printf("CAP_CHOWN is prohibited\n");
			break;
		case CAP_BLOCK_SUSPEND:
			printf("CAP_BLOCK_SUSPEND is prohibited\n");
			break;
		case CAP_SETUID:
			printf("CAP_SETUID is prohibited\n");
			break;
		case CAP_SETGID:
			printf("CAP_SETGID is prohibited\n");
			break;
		case CAP_FSETID:
			printf("CAP_SETFUID is prohibited\n");
			break;
		case CAP_KILL:
			printf("CAP_KILL is prohibited\n");
			break;
		case CAP_SYS_MODULE:
			printf("CAP_SYS_MODULE is prohibited\n");
			break;
		case CAP_SYS_TIME:
			printf("CAP_SYS_TIME is prohibited\n");
			break;
		case CAP_SYSLOG:
			printf("CAP_SYSLOG is prohibited\n");
			break;
		case CAP_SYS_PTRACE:
			printf("CAP_SYS_PTRACE is prohibited\n");
			break;
		case CAP_SYS_CHROOT:  /* */
			printf("CAP_SYS_CHROOT is prohibited\n");
			break;
		case CAP_IPC_OWNER:
			printf("CAP_IPC_OWNER is prohibited\n");
			break;
		default:
			goto allowed;
		}
	}


	if (prctl(PR_CAPBSET_DROP, cap, 0, 0, 0)) {
		if (cap > CAP_LAST_CAP)
		       return 0; /* header didn't know about this cap */
		if (errno == EINVAL) {
			/* if caps are disabled, this will spam */
			printf("cap not found: %lu\n", cap);
			return 0;
		}
		printf("PR_CAPBSET_DROP: %s\n", strerror(errno));
		return -1;
	}

allowed:
	return 0;
}


int clear_caps()
{
	struct __user_cap_header_struct hdr;
	struct __user_cap_data_struct   data[2];

	memset(&hdr, 0, sizeof(hdr));
	memset(data, 0, sizeof(data));

	hdr.pid = syscall(__NR_gettid);
	hdr.version = _LINUX_CAPABILITY_VERSION_3;
	if (capset(&hdr, data)) {
		printf("capset: %s\n", strerror(errno));
		printf("cap version: %p\n", (void *)hdr.version);
		printf("pid: %d\n", hdr.pid);
		return -1;
	}
	return 0;
}

/*
 * lock down the potential privileges that could be gained via filesystem
 * i don't think suid binaries are a good idea, so we use SECBIT_NOROOT
 *
 * a given fcap will be either 0 or 1
 *
 * returns 0,  -1 on error.
 */
int make_uncapable(char fcaps[64])
{
	int i;
	int c;

	/* remove from bounding set unless found in fcaps */
	for(i = 0; i < 64; ++i)
	{
		if (capbset_drop(i, fcaps))
			return -1;
	}

	/* don't grant privileges, except for file capabilities */
	if (prctl(PR_SET_SECUREBITS,
			SECBIT_KEEP_CAPS_LOCKED		|
			SECBIT_NO_SETUID_FIXUP		|
			SECBIT_NO_SETUID_FIXUP_LOCKED	|
			/** XXX if we decide to allow setuid binaries, remove these.
			 * but it complicates things a bit when file caps can solve
			 * the problem.  anything that needs uid 0 should be running
			 * as a service in some minimal namespace, i think.
			 * unfortunately this will lead to a lot of patches for common
			 * setuid programs,  ping, and whatnot.
			 */
			SECBIT_NOROOT			|
			SECBIT_NOROOT_LOCKED)) {

		printf("prctl(): %s\n", strerror(errno));
		return -1;
	}

	/* remove all process caps
	 * */
	/* caps are dropped when we call exec */
	/* TODO direct forked daemons are on their own to remove caps */

	/* if not requesting any file caps, set no new privs process flag */
	c = 0;
	for (i = 0; i < 64; ++i)
	{
		if (fcaps[i])
			++c;
	}
	if (c == 0) {
		printf("no file caps, setting NO_NEW_PRIVS\n");
		if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
			printf("no new privs failed\n");
	}

	return 0;

}










