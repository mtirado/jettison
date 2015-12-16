#include <stdio.h>
#include <string.h>
#include <linux/unistd.h>
#include <linux/audit.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/prctl.h>
#include "../util/seccomp_helper.h"
int syscalls[] = 
{
	__NR_read,
	__NR_write,
	__NR_open,
	__NR_close,
	__NR_mmap,
	__NR_exit
};

void fail(char *str)
{
	printf("%s failed: %s\n", str, strerror(errno));
	abort();
}

int main()
{
	int f;
	char buf[256];
	char out[] = "check one, two heyyyoo\n";

	printf("syscall translator output\n");
	printf("__NR_exit = %d\n", syscall_helper("__NR_exit"));
	printf("__NR_open = %d\n", syscall_helper("__NR_open"));
	printf("__NR_read = %d\n", syscall_helper("__NR_read"));
	printf("__NR_write = %d\n", syscall_helper("__NR_write"));


	printf("testing open, write, close with no seccomp filter\n");
	f = open("testfile1", O_CREAT | O_TRUNC | O_RDWR, 0700);
	if (f == -1)
		fail("open1");
	if (write(f, out, strlen(out)) == -1)
		fail("write1");
	close(f);


	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
		printf("prctl(): %s\n", strerror(errno));
		fail("prctl");
	}

	printf("applying syscall filter that blocks lseek\n");
	if (filter_syscalls(AUDIT_ARCH_I386, syscalls, /* nokill=1 XXX verify correct */
			       	sizeof(syscalls) / sizeof(int), 1)) {
		printf("unable to apply syscall filter\n");
		return -1;
	}

	printf("filter has been applied\n");

	memset(buf, 0, sizeof(buf));
	f = open("testfile1", O_RDONLY);
	if (f == -1)
		fail("open2");
	if (read(f, buf, sizeof(buf)-1) == -1)
		fail("read");
	sprintf(buf, "this should fail. \n");
	if (lseek(f, 0, SEEK_SET) != -1) {
		printf("lseek passed, test failed\n");
		abort();
	}

	printf("lseek returned -1: %s\n", strerror(errno));
	printf("test passed.\n");

	return 0;
}
