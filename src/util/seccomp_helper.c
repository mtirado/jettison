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
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/mount.h>
#include <sched.h>
#include <unistd.h>

#include <malloc.h>
#include <memory.h>
#include <errno.h>

#include <sys/syscall.h>
#include "../misc.h"
#include "seccomp_helper.h"
#include "../eslib/eslib.h"

/* translate config file strings to syscall number */
struct sc_translate
{
	char name[MAX_SYSCALL_DEFLEN];
	int  nr;
};

struct cap_translate
{
	char name[MAX_CAP_DEFLEN];
	int  nr;
};

struct cap_translate cap_table[] = {
{"CAP_CHOWN", CAP_CHOWN },
{"CAP_DAC_OVERRIDE", CAP_DAC_OVERRIDE },
{"CAP_DAC_READ_SEARCH", CAP_DAC_READ_SEARCH },
{"CAP_FOWNER", CAP_FOWNER },
{"CAP_FSETID", CAP_FSETID },
{"CAP_KILL", CAP_KILL },
{"CAP_SETGID", CAP_SETGID },
{"CAP_SETUID", CAP_SETUID },
{"CAP_SETPCAP", CAP_SETPCAP },
{"CAP_LINUX_IMMUTABLE", CAP_LINUX_IMMUTABLE },
{"CAP_NET_BIND_SERVICE", CAP_NET_BIND_SERVICE },
{"CAP_NET_BROADCAST", CAP_NET_BROADCAST },
{"CAP_NET_ADMIN", CAP_NET_ADMIN },
{"CAP_NET_RAW", CAP_NET_RAW },
{"CAP_IPC_LOCK", CAP_IPC_LOCK },
{"CAP_IPC_OWNER", CAP_IPC_OWNER },
{"CAP_SYS_MODULE", CAP_SYS_MODULE },
{"CAP_SYS_RAWIO", CAP_SYS_RAWIO },
{"CAP_SYS_CHROOT", CAP_SYS_CHROOT },
{"CAP_SYS_PTRACE", CAP_SYS_PTRACE },
{"CAP_SYS_PACCT", CAP_SYS_PACCT },
{"CAP_SYS_ADMIN", CAP_SYS_ADMIN },
{"CAP_SYS_BOOT", CAP_SYS_BOOT },
{"CAP_SYS_NICE", CAP_SYS_NICE },
{"CAP_SYS_RESOURCE", CAP_SYS_RESOURCE },
{"CAP_SYS_TIME", CAP_SYS_TIME },
{"CAP_SYS_TTY_CONFIG", CAP_SYS_TTY_CONFIG },
{"CAP_MKNOD", CAP_MKNOD },
{"CAP_LEASE", CAP_LEASE },
{"CAP_AUDIT_WRITE", CAP_AUDIT_WRITE },
{"CAP_AUDIT_CONTROL", CAP_AUDIT_CONTROL },
{"CAP_SETFCAP", CAP_SETFCAP },
{"CAP_MAC_OVERRIDE", CAP_MAC_OVERRIDE },
{"CAP_MAC_ADMIN", CAP_MAC_ADMIN },
{"CAP_SYSLOG", CAP_SYSLOG },
{"CAP_WAKE_ALARM", CAP_WAKE_ALARM },
{"CAP_BLOCK_SUSPEND", CAP_BLOCK_SUSPEND },
/*{"CAP_AUDIT_READ", CAP_AUDIT_READ },*/
};

/* XXX
 * there may be system calls missing if you're on a newer kernel.
 * if on an older kernel, you may need to comment out some syscalls.
 *
 * version: 4.1
 */
struct sc_translate sc_table[] = {
{ "__NR_restart_syscall", __NR_restart_syscall },
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
/* 3.10 */

/* 4.1 */
/*{ "__NR_sched_setattr", __NR_sched_setattr },
{ "__NR_sched_getattr", __NR_sched_getattr },
{ "__NR_renameat2", __NR_renameat2 },
{ "__NR_seccomp", __NR_seccomp },
{ "__NR_getrandom", __NR_getrandom },
{ "__NR_memfd_create", __NR_memfd_create },
{ "__NR_bpf", __NR_bpf },
{ "__NR_execveat", __NR_execveat },*/

/* 4.3 socket calls, huray!*/
/*{ "__NR_socket", __NR_socket },
{ "__NR_socketpair", __NR_socketpair },
{ "__NR_bind", __NR_bind },
{ "__NR_connect", __NR_connect },
{ "__NR_listen", __NR_listen },
{ "__NR_accept4", __NR_accept4 },
{ "__NR_getsockopt", __NR_getsockopt },
{ "__NR_setsockopt", __NR_setsockopt },
{ "__NR_getsockname", __NR_getsockname },
{ "__NR_getpeername", __NR_getpeername },
{ "__NR_sendto", __NR_sendto },
{ "__NR_sendmsg", __NR_sendmsg },
{ "__NR_recvfrom", __NR_recvfrom },
{ "__NR_recvmsg", __NR_recvmsg },
{ "__NR_shutdown", __NR_shutdown },
{ "__NR_userfaultfd", __NR_userfaultfd },
{ "__NR_membarrier", __NR_membarrier },
*/
};


unsigned int syscall_tablesize()
{
	return (sizeof(sc_table) / sizeof(struct sc_translate));
}
unsigned int syscall_gethighest()
{
	int high = 0;
	unsigned int i;
	unsigned int count = sizeof(sc_table) / sizeof(struct sc_translate);
	for (i = 0; i < count; ++i)
	{
		if (sc_table[i].nr > high)
			high = sc_table[i].nr;
	}
	return high;
}


int syscall_getnum(char *defstring)
{
	unsigned int i;
	unsigned int count;
	char buf[MAX_SYSCALL_DEFLEN];

	strncpy(buf, defstring, MAX_SYSCALL_DEFLEN-1);
	buf[MAX_SYSCALL_DEFLEN-1] = '\0';
	count = sizeof(sc_table) / sizeof(struct sc_translate);
	for (i = 0; i < count; ++i)
	{
		if (strncmp(buf, sc_table[i].name, MAX_SYSCALL_DEFLEN) == 0)
			return sc_table[i].nr;
	}
	return -1;
}

char *syscall_getname(long syscall_nr)
{
	long count;
	int i;

	count = sizeof(sc_table) / sizeof(struct sc_translate);
	if (syscall_nr < 0)
		return NULL;

	for (i = 0; i < count; ++i)
	{
		if (sc_table[i].nr == syscall_nr)
			return sc_table[i].name;
	}
	return NULL;
}

int cap_getnum(char *defstring)
{
	unsigned int i;
	unsigned int count;
	char buf[MAX_CAP_DEFLEN];

	strncpy(buf, defstring, MAX_CAP_DEFLEN-1);
	buf[MAX_CAP_DEFLEN-1] = '\0';
	count = sizeof(cap_table) / sizeof(struct cap_translate);
	for (i = 0; i < count; ++i)
	{
		if (strncmp(buf, cap_table[i].name, MAX_CAP_DEFLEN) == 0)
			return cap_table[i].nr;
	}
	return -1;
}

/* number of systemcalls in a given number array ( -1 is invalid )*/
unsigned int count_syscalls(int *syscalls, unsigned int count)
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
 * helper functions to de-uglify seccomp-bpf instructions
 * note: i is incremented by this macro!
 */
#define SECBPF_INSTR(p__, i__, c__, t__, f__, k__)	\
{							\
	p__[i__].code = c__;				\
	p__[i__].jt   = t__;				\
	p__[i__].jf   = f__;				\
	p__[i__].k    = k__;				\
	++i__;						\
}
#define SECBPF_LD_ABSW(p_,i_,k_)   SECBPF_INSTR(p_,i_,(BPF_LD|BPF_W|BPF_ABS),0,0,k_)
#define SECBPF_JEQ(p_,i_,k_,t_,f_) SECBPF_INSTR(p_,i_,(BPF_JMP|BPF_JEQ|BPF_K),t_,f_,k_)
#define SECBPF_JMP(p_,i_,k_)       SECBPF_INSTR(p_,i_,(BPF_JMP|BPF_JA),0,0,k_)
#define SECBPF_RET(p_,i_,k_)       SECBPF_INSTR(p_,i_,(BPF_RET|BPF_K),0,0,k_)
#define SECDAT_ARG0                offsetof(struct seccomp_data,args[0])
#define SECDAT_ARCH                offsetof(struct seccomp_data,arch)
#define SECDAT_NR                  offsetof(struct seccomp_data,nr)


static struct sock_filter *build_seccomp_filter(int arch, int *whitelist, int *blocklist,
		unsigned int wcount, unsigned int bcount, unsigned int *instr_count,
		unsigned int options, long retaction)
{
	unsigned int i,z;
	unsigned int proglen;
	unsigned int count;
	struct sock_filter *prog = NULL;

	if (bcount > 0 && wcount <= 0) {
		printf("error, cannot use seccomp_block without any seccomp_allow\n");
		return NULL;
	}
	count = wcount + bcount;
	if (count > 2000) {
		printf("2000 syscalls maximum\n");
		return NULL;
	}
	printf("whitelist count: %d\r\n", wcount);
	printf("blocklist count: %d\r\n", bcount);

	proglen = 4 + (count * 2) + 1;
	/* whitelist for init process */
	if (count > 0)
		proglen += 18;
	if (options & SECCOPT_BLOCKNEW) {
		proglen += 7;
	}
	if (!(options & SECCOPT_PTRACE)) {
		proglen += 2;
	}


	prog = malloc(proglen * sizeof(struct sock_filter));
	if (prog == NULL)
		return NULL;

	/* create seccomp bpf filter */
	memset(prog, 0, proglen * sizeof(struct sock_filter));
	i = 0;

	/* validate arch */
	SECBPF_LD_ABSW(prog, i, SECDAT_ARCH);
	SECBPF_JEQ(prog, i, arch, 1, 0);
	SECBPF_RET(prog, i, SECCOMP_RET_KILL);

	/* load syscall number */
	SECBPF_LD_ABSW(prog, i, SECDAT_NR);

	 /* we must not allow ptrace if process can install filters
	  * or if filter may contain SECCOMP_RET_TRACE see documentation.
	  * to be safe, lets just outright banish ptrace inside sandbox
	  * unless user requests this (ptrace debuggers/crash reporters)
	  */
	if (!(options & SECCOPT_PTRACE)) {
		SECBPF_JEQ(prog, i, __NR_ptrace, 0, 1);
		SECBPF_RET(prog, i, SECCOMP_RET_TRAP);
	}
	/* has to be done at start of filter, which degrades performance.
	 * we can eliminate this with a new prctl to block filters
	 * will save cpu time on high frequency system calls.
	 */
	if (options & SECCOPT_BLOCKNEW) {
#ifdef __NR_seccomp /* since kernel 3.17 */
		SECBPF_JEQ(prog, i, __NR_seccomp, 0, 1);
		SECBPF_RET(prog, i, SECCOMP_RET_ERRNO|(ENOSYS & SECCOMP_RET_DATA));
#else
		SECBPF_JMP(prog, i, 1);
		SECBPF_JMP(prog, i, 0);
#endif
		SECBPF_JEQ(prog, i, __NR_prctl, 0, 4);
		SECBPF_LD_ABSW(prog, i, SECDAT_ARG0); /* load prctl arg0 */
		SECBPF_JEQ(prog, i, PR_SET_SECCOMP, 0, 1);
		SECBPF_RET(prog, i, SECCOMP_RET_ERRNO|(ENOSYS & SECCOMP_RET_DATA));
		SECBPF_LD_ABSW(prog, i, SECDAT_NR); /* restore */
	}


	/* everything is whitelisted if count is 0, this is end of filter */
	if (count == 0) {
		SECBPF_RET(prog, i, SECCOMP_RET_ALLOW);
		*instr_count = proglen;
		printf("---------------------------------\n");
		printf(" warning: no seccomp whitelist\n");
		printf("--------------------------------\n");
		return prog;
	}

	/* generate whitelist jumps */
	for (z = 0; z < wcount; ++z)
	{
		if (whitelist[z] == -1) {
			printf("invalid syscall: z(%d)\n", z);
			free(prog);
			return NULL;
		}
		SECBPF_JEQ(prog, i, whitelist[z], 0, 1);
		SECBPF_RET(prog, i, SECCOMP_RET_ALLOW);
	}

	/* generate blocklist jumps */
	for (z = 0; z < bcount; ++z)
	{
		if (blocklist[z] == -1) {
			printf("invalid syscall: z(%d)\n", z);
			free(prog);
			return NULL;
		}
		SECBPF_JEQ(prog, i, blocklist[z], 0, 1);
		SECBPF_RET(prog,i,SECCOMP_RET_ERRNO|(ENOSYS & SECCOMP_RET_DATA));
	}

	/* our init process needs to setup signals, fork exec waitpid kill exit */
	SECBPF_JEQ(prog, i, __NR_sigaction, 0, 1);
	SECBPF_RET(prog, i, SECCOMP_RET_ALLOW);
	SECBPF_JEQ(prog, i, __NR_sigreturn, 0, 1);
	SECBPF_RET(prog, i, SECCOMP_RET_ALLOW);
	SECBPF_JEQ(prog, i, __NR_clone, 0, 1);
	SECBPF_RET(prog, i, SECCOMP_RET_ALLOW);
	SECBPF_JEQ(prog, i, __NR_waitpid, 0, 1);
	SECBPF_RET(prog, i, SECCOMP_RET_ALLOW);
	SECBPF_JEQ(prog, i, __NR_kill, 0, 1);
	SECBPF_RET(prog, i, SECCOMP_RET_ALLOW);
	SECBPF_JEQ(prog, i, __NR_nanosleep, 0, 1);
	SECBPF_RET(prog, i, SECCOMP_RET_ALLOW);
	SECBPF_JEQ(prog, i, __NR_exit, 0, 1);
	SECBPF_RET(prog, i, SECCOMP_RET_ALLOW);
	SECBPF_JEQ(prog, i, __NR_exit_group, 0, 1);
	SECBPF_RET(prog, i, SECCOMP_RET_ALLOW);
	/* TODO some decent hack to disable exec after init calls it */
	SECBPF_JEQ(prog, i, __NR_execve, 0, 1);
	SECBPF_RET(prog, i, SECCOMP_RET_ALLOW);

	/* set return action */
	switch (retaction)
	{
	case SECCOMP_RET_TRAP:
		printf("SECCOMP_RET_TRAP\r\n");
		SECBPF_RET(prog,i,SECCOMP_RET_TRAP|(SECCRET_DENIED & SECCOMP_RET_DATA));
		break;
	case SECCOMP_RET_KILL:
		printf("SECCOMP_RET_KILL\r\n");
		SECBPF_RET(prog,i,SECCOMP_RET_KILL);
		break;
	case SECCOMP_RET_ERRNO:
		printf("SECCOMP_RET_ERRNO\r\n");
		SECBPF_RET(prog,i,SECCOMP_RET_ERRNO|(ENOSYS & SECCOMP_RET_DATA));
		break;
	default:
		printf("invalid return action\n");
		free(prog);
		return NULL;
	}

	*instr_count = proglen;
	return prog;
}


int filter_syscalls(int arch, int *whitelist, int *blocklist,
		    unsigned int wcount, unsigned int bcount,
		    unsigned int options, long retaction)
{
	struct sock_filter *filter;
	struct sock_fprog prog;
	unsigned int instr_count;

	if (!whitelist)
		return -1;
	if (!blocklist)
		bcount = 0;

	filter = build_seccomp_filter(arch, whitelist, blocklist, wcount,
				      bcount, &instr_count, options, retaction);
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
	free(filter);
	return 0;
}


/*
 * drop all caps from thread, unless pod requested them.
 * set capability bounding set to prevent thread from gaining privileges
 * such as MKNOD, SET_FCAP, SET_PCAP, etc...
 *
 */
extern int capset(cap_user_header_t header, cap_user_data_t data);
extern int capget(cap_user_header_t header, const cap_user_data_t data);

static int cap_blisted(unsigned long cap)
{
	if (cap >= NUM_OF_CAPS) {
		printf("cap out of bounds\n");
		return 1;
	}

	/* is pod requesting we allow file cap? */
	/*
	 * FILE CAP BLACKLIST
	 * some caps should never be allowed (MKNOD, SYS_MODULE!!)
	 * SYS_ADMIN would allow remounting files to change mount flags,
	 * and possibly exploit privileged programs (LD_PRELOAD style)
	 */
	switch(cap)
	{
		case CAP_MKNOD:
			printf("CAP_MKNOD is prohibited\n");
			return 1;
		case CAP_SYS_MODULE:
			printf("CAP_SYS_MODULE is prohibited\n");
			return 1;
		case CAP_SETPCAP:
			printf("CAP_SETPCAP is prohibited\n");
			return 1;
		case CAP_SETFCAP:
			printf("CAP_SETFCAP is prohibited\n");
			return 1;
		case CAP_DAC_OVERRIDE:
			printf("CAP_DAC_OVERRIDE is prohibited\n");
			return 1;
		case CAP_SYS_ADMIN: /* don't allow remounts... */
			printf("CAP_SYS_ADMIN is prohibited\n");
			return 1;
		case CAP_LINUX_IMMUTABLE:
			printf("CAP_LINUX_IMMUTABLE is prohibited\n");
			return 1;
		/*case CAP_DAC_READ_SEARCH:
			printf("CAP_DAC_READ_SEARCH is prohibited\n");
			return 1;*/
		case CAP_MAC_OVERRIDE:
			printf("CAP_MAC_OVERRIDE is prohibited\n");
			return 1;
		case CAP_MAC_ADMIN:
			printf("CAP_MAC_ADMIN is prohibited\n");
			return 1;
		case CAP_CHOWN:
			printf("CAP_CHOWN is prohibited\n");
			return 1;
		case CAP_BLOCK_SUSPEND:
			printf("CAP_BLOCK_SUSPEND is prohibited\n");
			return 1;
		case CAP_SETUID:
			printf("CAP_SETUID is prohibited\n");
			return 1;
		case CAP_SETGID:
			printf("CAP_SETGID is prohibited\n");
			return 1;
		case CAP_FSETID:
			printf("CAP_SETFUID is prohibited\n");
			return 1;
		case CAP_KILL:
			printf("CAP_KILL is prohibited\n");
			return 1;
		case CAP_SYS_TIME:
			printf("CAP_SYS_TIME is prohibited\n");
			return 1;
		case CAP_SYSLOG:
			printf("CAP_SYSLOG is prohibited\n");
			return 1;
		case CAP_SYS_PTRACE:
			printf("CAP_SYS_PTRACE is prohibited\n");
			return 1;
		case CAP_SYS_CHROOT:  /* be weary of ld_preload style abuse if enabled */
			printf("CAP_SYS_CHROOT is prohibited\n");
			return 1;
		case CAP_IPC_OWNER:
			printf("CAP_IPC_OWNER is prohibited\n");
			return 1;
	default:
		return 0;
	}

}

/* e,p,i are which caps to set effective, permitted, inheritable
 * to gain effective capability, it must already be in permitted set
 * pass NULL to clear all */
int set_caps(int cap_e[NUM_OF_CAPS], int cap_p[NUM_OF_CAPS], int cap_i[NUM_OF_CAPS])
{
	struct __user_cap_header_struct hdr;
	struct __user_cap_data_struct   data[2];
	int i;
	int inheriting = 0;
	unsigned long secbits;
	memset(&hdr, 0, sizeof(hdr));
	memset(data, 0, sizeof(data));
	hdr.pid = syscall(__NR_gettid);
	hdr.version = _LINUX_CAPABILITY_VERSION_3;

	for(i = 0; i < NUM_OF_CAPS; ++i)
	{
		if (cap_e && cap_e[i])
			data[CAP_TO_INDEX(i)].effective |= CAP_TO_MASK(i);
		if (cap_p && cap_p[i])
			data[CAP_TO_INDEX(i)].permitted	|= CAP_TO_MASK(i);
		if (cap_i && cap_i[i]) {
			data[CAP_TO_INDEX(i)].inheritable |= CAP_TO_MASK(i);
			inheriting = 1;
		}

		/* clear bounding set, unless inheriting */
		if (cap_i == NULL || cap_i[i] != 1) {
			if (prctl(PR_CAPBSET_DROP, i, 0, 0, 0)) {
				if (i > CAP_LAST_CAP) {
					break;
				}
				else if (errno == EINVAL) {
					printf("cap not found: %d\n", i);
					return -1;
				}
				printf("PR_CAPBSET_DROP: %s\n", strerror(errno));
				return -1;
			}
		}
	}

	secbits = SECBIT_KEEP_CAPS_LOCKED	|
		  SECBIT_NO_SETUID_FIXUP	|
		  SECBIT_NO_SETUID_FIXUP_LOCKED;
	if (!inheriting) {
		  secbits |= SECBIT_NOROOT | SECBIT_NOROOT_LOCKED;
	}
	if (prctl(PR_SET_SECUREBITS, secbits)) {
		printf("prctl(): %s\n", strerror(errno));
		return -1;
	}

	if (capset(&hdr, data)) {
		printf("capset: %s\n", strerror(errno));
		printf("cap version: %p\n", (void *)hdr.version);
		printf("pid: %d\n", hdr.pid);
		return -1;
	}
	return 0;
}

int print_caps()
{
	struct __user_cap_header_struct hdr;
	struct __user_cap_data_struct   data[2];

	hdr.pid = syscall(__NR_gettid);
	hdr.version = _LINUX_CAPABILITY_VERSION_3;
	if (capget(&hdr, data)) {
		printf("capget: %s\r\n", strerror(errno));
		return -1;
	}
	printf("\reffective: %08x", data[0].effective);
	printf("%08x\r\n", data[1].effective);
	printf("permitted: %08x", data[0].permitted);
	printf("%08x\r\n", data[1].permitted);
	printf("inheritable: %08x", data[0].inheritable);
	printf("%08x\r\n", data[1].inheritable);
	return 0;
}

/*
 * remove all capabilities this program does not require,
 * setuid defensive measure, just in case.
 * returns 0,  -1 on error.
 */
int downgrade_caps()
{
	struct __user_cap_header_struct hdr;
	struct __user_cap_data_struct   data[2];
	int i;

	memset(&hdr, 0, sizeof(hdr));
	memset(data, 0, sizeof(data));
	hdr.pid = syscall(__NR_gettid);
	hdr.version = _LINUX_CAPABILITY_VERSION_3;

	for(i = 0; i < NUM_OF_CAPS; ++i)
	{
		/* we need to temporarily hold on to these caps
		 * TODO drop setuid if not using --lognet, and net_admin
		 * and net_raw if not using ipvlan / --lognet */
		if (i == CAP_SYS_CHROOT
				|| i == CAP_SYS_ADMIN
				|| i == CAP_NET_ADMIN
				|| i == CAP_NET_RAW
				|| i == CAP_CHOWN
				|| i == CAP_SETGID
				|| i == CAP_SETUID
				|| i == CAP_SETPCAP) {
			data[CAP_TO_INDEX(i)].permitted |= CAP_TO_MASK(i);
			/* these dont need to be in effective set */
			if (i != CAP_NET_RAW && i != CAP_SETUID) {
				data[CAP_TO_INDEX(i)].effective |= CAP_TO_MASK(i);
			}
		}
	}
	/* don't grant caps on uid change */
	if (prctl(PR_SET_SECUREBITS,
			SECBIT_KEEP_CAPS_LOCKED		|
			SECBIT_NO_SETUID_FIXUP		|
			SECBIT_NO_SETUID_FIXUP_LOCKED)) {
		printf("prctl(): %s\n", strerror(errno));
		return -1;
	}

	if (capset(&hdr, data)) {
		printf("capset: %s\r\n", strerror(errno));
		printf("cap version: %p\r\n", (void *)hdr.version);
		printf("pid: %d\r\n", hdr.pid);
		return -1;
	}

	return 0;
}

int capbset_drop(int fcaps[NUM_OF_CAPS])
{
	int i;
	int c;

	c = 0;
	for(i = 0; i < NUM_OF_CAPS; ++i)
	{
		/* allow requested file caps if not blacklisted */
		if (fcaps[i] && !cap_blisted(i)) {
			if (i > CAP_LAST_CAP) {
			       return -1;
			}
			++c;
		}
		else if (prctl(PR_CAPBSET_DROP, i, 0, 0, 0)) {
			if (i > CAP_LAST_CAP)
				break;
			else if (errno == EINVAL) {
				printf("cap not found: %d\n", i);
				return -1;
			}
			printf("PR_CAPBSET_DROP: %s\n", strerror(errno));
			return -1;
		}
	}
	/* if not requesting any file caps, set no new privs process flag */
	if (c == 0) {
		printf("no file caps, setting NO_NEW_PRIVS\r\n");
		if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
			printf("no new privs failed\n");
			return -1;
		}
	}

	/* lock down caps for the program exec */
	if (prctl(PR_SET_SECUREBITS,
			 SECBIT_KEEP_CAPS_LOCKED
			|SECBIT_NO_SETUID_FIXUP
			|SECBIT_NO_SETUID_FIXUP_LOCKED
			|SECBIT_NOROOT
			|SECBIT_NOROOT_LOCKED)) {
		printf("prctl(): %s\n", strerror(errno));
		return -1;
	}
	return 0;
}

int jail_process(char *chroot_path,
		 uid_t set_reuid,
		 gid_t set_regid,
		 int  *whitelist,
		 unsigned long seccomp_opts,
		 int cap_e[NUM_OF_CAPS],
		 int cap_p[NUM_OF_CAPS],
		 int cap_i[NUM_OF_CAPS],
		 int can_write,
		 int can_exec)
{

	unsigned long remountflags = MS_REMOUNT
				   | MS_NOSUID
				   | MS_NODEV;

	if (eslib_file_path_check(chroot_path))
		return -1;

	if (!can_write)
		remountflags |= MS_RDONLY;
	if (!can_exec)
		remountflags |= MS_NOEXEC;

	if (mount(chroot_path, chroot_path, "bind", MS_BIND, NULL)) {
		printf("could not bind mount: %s\n", strerror(errno));
		return -1;
	}
	if (mount(chroot_path, chroot_path, "bind", MS_BIND|remountflags, NULL)) {
		printf("could not bind mount: %s\n", strerror(errno));
		return -1;
	}
	if (mount(NULL, chroot_path, NULL, MS_PRIVATE|MS_REC, NULL)) {
		printf("could not make slave: %s\n", strerror(errno));
		return -1;
	}
	if (chdir(chroot_path) < 0) {
		printf("chdir(\"%s\") failed: %s\n", chroot_path, strerror(errno));
		return -1;
	}
	if (mount(chroot_path, "/", NULL, MS_MOVE, NULL) < 0) {
		printf("mount / MS_MOVE failed: %s\n", strerror(errno));
		return -1;
	}
	if (chroot(chroot_path) < 0) {
		printf("chroot failed: %s\n", strerror(errno));
		return -1;
	}
	/*chroot doesnt change CWD, so we must.*/
	if (chdir("/") < 0) {
		printf("chdir(\"/\") failed: %s\n", strerror(errno));
		return -1;
	}

	if (set_regid && setregid(set_regid, set_regid)) {
		printf("error setting gid(%d): %s\n", set_regid, strerror(errno));
		return -1;
	}
        if (set_reuid && setreuid(set_reuid, set_reuid)) {
		printf("error setting uid(%d): %s\n", set_reuid, strerror(errno));
		return -1;
	}
	if (set_caps(cap_e, cap_p, cap_i)) {
		printf("set_caps failed\n");
		return -1;
	}

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
		printf("set no new privs failed\n");
		return -1;
	}

	if (whitelist && filter_syscalls(SYSCALL_ARCH, whitelist, NULL,
				 count_syscalls(whitelist, MAX_SYSCALLS), 0,
				 seccomp_opts, SECCOMP_RET_ERRNO)) {
		/* TODO eventually set this to RET_KILL */
		printf("unable to apply seccomp filter\n");
		return -1;
	}
	else if (whitelist) {
		printf("seccomp filter set \r\n");
	}
	return 0;
}
