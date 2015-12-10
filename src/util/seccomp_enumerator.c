/* (c) 2015 Michael R. Tirado -- GPLv3, GNU General Public License, version 3.
 *
 * used this program to generate a list of seccomp pod options for each
 * system call located in the input file.
 *
 * use 'strace -o filename -f -c -S calls program'  to generate input file
 * this will gather any system calls a program makes so you will need
 * to test all functionality of the program to get a complete list
 *
 * changing seccomp behavior from kill to errno will greatly aid in identifying
 * what syscalls a process is trying to call
 *
 *
 * XXX BUGS ? XXX  -- can we make strace print the *actual* syscall somehow?
 * i only tested on i686, hopefully it's the only completely screwed up arch.
 *
 * on some arch's __NR_socketcall may be needed instead of:
 *	__NR_socket
 *	__NR_bind
 *	__NR_connect
 *	__NR_listen
 *	__NR_accept
 *	__NR_getsockname
 *	__NR_getpeername
 *	__NR_socketpair
 *	__NR_send
 *	__NR_recv
 *	__NR_sendto
 *	__NR_recvfrom
 *	__NR_shutdown
 *	__NR_setsockopt
 *	__NR_getsockopt
 *	__NR_sendmsg
 *	__NR_recvmsg
 *
 *	__NR_select should probably also add __NR__newselect
 *
 *	also, __NR_ipc instead of:
 *	__NR_semop
 *	__NR_semget
 *	__NR_semctl
 *	__NR_semtimedop
 *	__NR_msgsnd
 *	__NR_msgrcv
 *	__NR_msgget
 *	__NR_msgctl
 *	__NR_shmat
 *	__NR_shmdt
 *	__NR_shmget
 *	__NR_shmctl
 *
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <memory.h>

#define MAX_FILEDAT 1024 * 1024 /* 1MB is plenty big */
#define MAX_SYSCALLS 1024 /* as of 4.2 we're at around 350? */
#define MAX_STR 128
struct item
{
	char str[MAX_STR];  /* system call string */
};

static void usage()
{
	printf("usage: seccomp_enumerator <input-file> <output-file>\n\n");
	printf("use strace -f -c -S calls -o <input> <program> to generate input\n");
	printf("-S calls sorts by most frequent syscall, for optimized whitelist\n");
	_exit(-1);
}

int main(int argc, char *argv[])
{
	int in;
	int out;
	int r;
	size_t size;
	struct item syscalls[MAX_SYSCALLS];
	char fdata[MAX_FILEDAT];
	char tmp[MAX_STR-6];
	unsigned int i;
	unsigned int newline;
	unsigned int scan;
	unsigned int idx;
	unsigned int len;
	memset(fdata, 0, sizeof(fdata));
	memset(syscalls, 0, sizeof(syscalls));

	/* open files */
	if (argc != 3)
		usage();
	in = open(argv[1], O_RDONLY, 0);
	if (in == -1) {
		printf("could not open input file(%s): %s\n", strerror(errno), argv[1]);
		return -1;
	}
	out = open(argv[2], O_RDWR|O_CREAT|O_TRUNC, 0750);
	if (out == -1) {
		printf("could not create output file(%s): %s\n", strerror(errno), argv[2]);
		return -1;
	}

	size = lseek(in, 0, SEEK_END);
	lseek(in, 0, SEEK_SET);

	if (size >= MAX_FILEDAT || size < 10) {
		printf("file too large...\n");
		usage();
	}
	/* read file data */
	r = read(in, fdata, sizeof(fdata)-1);
	if (r == -1) {
		printf("read: %s\n", strerror(errno));
		return -1;
	}
	close(in);

	/* process file data */
	idx = 0;
	i = 1;

	/* find line with '-----' (should be second line) */
	for (; i < size; ++i)
	{
		if (fdata[i] == '\n') {
			if (fdata[i-1] == '-') {
				++i;
				break;
			}
		}
	}
	if (i >= size) {
		printf("unexpected eof\n");
		usage();
	}

	newline = i;
	/* should now be on first line with syscalls,
	 * line starting with - means we're at end
	 */
	while (i < size)
	{
		if (fdata[i] == '-')
			break;
		scan = i;
		/* find newline */
		if (fdata[i] == '\n') {
			/* rewind to name start */
			while(scan >= newline)
			{
				if (fdata[scan] == ' ' || fdata[scan] == '\t') {
					if (fdata[++scan] == '\n')
						goto parse_error;
					len = i - scan;
					if (len >= MAX_STR-1)
						goto parse_error;
					strncpy(tmp, &fdata[scan], len);
					tmp[len] = '\0';
					snprintf(syscalls[idx].str, MAX_STR, "__NR_%s", tmp);

					if (++idx >= MAX_SYSCALLS)
						goto parse_error;
					break;
				}
				--scan;
			}
			if (scan < newline)
				goto parse_error;
			newline = i+1;
		}
		++i;
	}
	if (i >= size || idx == 0) {
		printf("unexpected eof\n");
		usage();
	}

	/* write output file */
	for (i = 0; i < idx; ++i)
	{
		char buf[MAX_STR];
		snprintf(buf, MAX_STR, "seccomp_allow %s\n", syscalls[i].str);
		len = strnlen(buf, MAX_STR);
		if (len >= MAX_STR)
			goto parse_error;
		r = write(out, buf, len);
	}
	close(out);
	return 0;

parse_error:
	printf("parse error\n");
	usage();
	return -1;
}










