/* (c) 2015 Michael R. Tirado -- GPLv3, GNU General Public License, version 3.
 * contact: mtirado418@gmail.com
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
#include "../eslib/eslib_fortify.h"

extern int capset(cap_user_header_t header, cap_user_data_t data);
extern int capget(cap_user_header_t header, const cap_user_data_t data);

/*
 * remove all capabilities this program does not require,
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
		if (fcaps[i] && !cap_blacklisted(i)) {
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


