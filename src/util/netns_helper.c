/* (c) 2015 Michael R. Tirado -- GPLv3, GNU General Public License, version 3.
 * contact: mtirado418@gmail.com
 */
#define _GNU_SOURCE
#include <linux/unistd.h>
#include <stdio.h>
#include <errno.h>
#include <sched.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/capability.h>
#include <unistd.h>
#include <string.h>
#include "../eslib/eslib.h"
#include "../eslib/eslib_rtnetlink.h"
#include "../pod.h"

/* reimplementing these in eslib would take quite a bit of time and
 * less flexible than using admin's program of choice, we can set pod
 * specific rules in /etc/pods/<pod>/netfilter or elsewhere...
 * or match program name with filter /etc/pods/netfilter/<progname>
 *  ^^ TODO ^^
 */
#ifndef FIREWALL_SAVE
	#define FIREWALL_SAVE "iptables-save"
#endif
#ifndef FIREWALL_RESTORE
	#define FIREWALL_RESTORE "iptables-restore"
#endif
#ifndef FIREWALL_RULE
	#define FIREWALL_RULE "iptables"
#endif
#ifndef FIREWALL_PROG
	#define FIREWALL_PROG "/usr/sbin/xtables-multi"
#endif

/* external globals in jettison.c */
extern uid_t g_ruid;
extern gid_t g_rgid;
extern pid_t g_initpid;
extern struct newnet_param g_newnet;
extern char **environ;

int netns_restore_firewall(char *buf, int size);
int netns_save_firewall(char *buf, int size);

static int netns_lo_config()
{
	int r;
	r = eslib_rtnetlink_linkset("lo", RTNL_LINKUP);
	if (r) {
		printf("couldn't set lo up\n");
		(r == 1) ? printf("nack\n") : printf("error\n");
		return -1;
	}
	return 0;
}

static int netns_vlan_config(char *ifname, char *gateway)
{
	char *dev = g_newnet.dev;
	int r;
	if (!dev || !ifname || !gateway) {
		printf("invalid vlan_config params\n");
		return -1;
	}

	/* set loopback up */
	r = eslib_rtnetlink_linkset("lo", RTNL_LINKUP);
	if (r) {
		printf("couldn't set lo up\n");
		(r == 1) ? printf("nack\n") : printf("error\n");
		return -1;
	}
	/* rename device in new namespace to match rootns name */
	r = eslib_rtnetlink_linksetname(ifname, dev);
	if (r) {
		printf("couldn't set interface name\n");
		(r == 1) ? printf("nack\n") : printf("error\n");
		return -1;
	}
	/* set up */
	r = eslib_rtnetlink_linkset(dev, RTNL_LINKUP);
	if (r) {
		printf("couldn't set %s up\n", ifname);
		(r == 1) ? printf("nack\n") : printf("error\n");
		eslib_rtnetlink_linkdel(ifname);
		return -1;
	}
	/* set address */
	r = eslib_rtnetlink_linkaddr(dev, g_newnet.addr, g_newnet.netmask);
	if (r) {
		printf("couldn't add address(%s/%d) to iface %s\n",
				g_newnet.addr, g_newnet.netmask, dev);
		(r == 1) ? printf("nack\n") : printf("error\n");
		eslib_rtnetlink_linkdel(ifname);
		return -1;
	}
	/* set gateway */
	printf("\n\ndev/addr/mask: %s %s %d\n", dev, g_newnet.addr, g_newnet.netmask);
	r = eslib_rtnetlink_setgateway(dev, g_newnet.gateway);
	if (r) {
		printf("couldn't set gateway for iface %s\n", dev);
		(r == 1) ? printf("nack\n") : printf("error\n");
		eslib_rtnetlink_linkdel(ifname);
		return -1;
	}
	return 0;
}

/* std_io should be a socketpair int std_io[2], [0] current thread [1] new thread*/
static int do_exec(char *path, char *argv[], int *std_io, char *inbuf, int bufsize)
{
	pid_t p;
	int status;

	if (!path || !argv || (inbuf && !std_io))
		return -1;
	if (strnlen(path, MAX_SYSTEMPATH) >= MAX_SYSTEMPATH)
		return -1;

	p = fork();
	if (p == -1) {
		printf("fork(): %s\n", strerror(errno));
		return -1;
	}
	else if (p == 0) {
		struct __user_cap_header_struct hdr;
		struct __user_cap_data_struct   data[2];

		if (std_io) {
			if (dup2(std_io[1], STDIN_FILENO) != STDIN_FILENO
				|| dup2(std_io[1], STDOUT_FILENO) != STDOUT_FILENO
				|| dup2(std_io[1], STDERR_FILENO) != STDERR_FILENO) {
				printf("stdio replacement failure\n");
				return -1;
			}
		}
		/* let exec inherit CAP_NET_ADMIN */
		memset(&hdr, 0, sizeof(hdr));
		memset(data, 0, sizeof(data));
		hdr.pid = syscall(__NR_gettid);
		hdr.version = _LINUX_CAPABILITY_VERSION_3;

		data[CAP_TO_INDEX(CAP_NET_ADMIN)].effective
			|= CAP_TO_MASK(CAP_NET_ADMIN);
		data[CAP_TO_INDEX(CAP_NET_ADMIN)].permitted
			|= CAP_TO_MASK(CAP_NET_ADMIN);
		data[CAP_TO_INDEX(CAP_NET_ADMIN)].inheritable
			|= CAP_TO_MASK(CAP_NET_ADMIN);

		if (capset(&hdr, data)) {
			printf("capset: %s\r\n", strerror(errno));
			printf("cap version: %p\r\n", (void *)hdr.version);
			printf("pid: %d\r\n", hdr.pid);
			return -1;
		}

		if (execve(path, argv, environ)) {
			printf("execve: %s\n", strerror(errno));
			_exit(-1);
		}
		_exit(0);
	}

	/* pipe input to new program */
	if (inbuf && std_io) {
		int bytesleft = bufsize;
		if (bufsize <= 0)
			return -1;
		while(1)
		{
			int w = write(std_io[0], inbuf, bytesleft);
			if (w == -1 && (errno == EINTR||errno == EAGAIN))
				continue;
			else if (w == -1 || w == 0) {
				printf("write: %s\n", strerror(errno));
				return -1;
			}
			bytesleft -= w;
			inbuf += w;
			if (bytesleft == 0) {
				shutdown(std_io[0], SHUT_WR);
				break;
			}
			else if (bytesleft < 0) {
				printf("write size error\n");
				return -1;
			}
		}
	}
	/* wait for program return code */
	while (1)
	{
		int r = waitpid(p, &status, 0);
		if (r == -1 && errno == EINTR) {
			continue;
		}
		else if (r == p) {
			break;
		}
		else {
			printf("waitpid(%d) error: %s\n", p, strerror(errno));
			return -1;
		}
	}
	if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
		return 0;
	}
	printf("%s program encountered an error\n", path);
	return -1;
}


/*
 * enter new namespace and hookup with the root namespace device
 */
static int netns_enter_and_config(char *ifname, pid_t target)
{
	pid_t p;
	int status;
	int r;

	/* save current firewall for new net namespace */
	r = netns_save_firewall(g_newnet.netfilter, sizeof(g_newnet.netfilter));
	if (r <= 0) {
		printf("couldn't save firewall rules\n");
		return -1;
	}
	g_newnet.filtersize = r;
	p = fork();
	if (p == -1) {
		printf("fork\n");
		return -1;
	}
	else if (p == 0) /* new process */
	{
		char path[MAX_SYSTEMPATH];
		int nsfd;
		int retries = 10;
		/* open target namespace */
		setuid(g_ruid);
		setgid(g_rgid);
		snprintf(path, sizeof(path), "/proc/%d/ns/net", target);
		while (retries > 0)
		{
			nsfd = open(path, O_RDONLY);
			if (nsfd == -1) {
				if (--retries < 0) {
					printf("open(%s): %s\n", path, strerror(errno));
					_exit(-1);
				}
				usleep(100000);
			}
			else {
				break;
			}
		}
		setuid(0);
		setgid(0);

		/* enter namespace */
		if (setns(nsfd, CLONE_NEWNET)) {
			printf("setns(newnet): %s\n", strerror(errno));
			close(nsfd);
			_exit(-1);
		}
		close(nsfd);

		switch (g_newnet.kind)
		{
		case RTNL_KIND_LOOP:
			if (netns_lo_config()) {
				printf("loopback config failed\n");
				_exit(-1);
			}
			break;
		case RTNL_KIND_IPVLAN:
			if (netns_vlan_config(ifname, g_newnet.gateway)) {
				printf("vlan config failed\n");
				_exit(-1);
			}
			break;
		default:
			printf("net interface kind: %d\n", g_newnet.kind);
			_exit(-1);
			break;
		}

		/* restore firewall */
		if (g_newnet.filtersize) {
			if (netns_restore_firewall(g_newnet.netfilter,
						   g_newnet.filtersize)) {
				printf("couldn't install netfilter\n");
				return -1;
			}
		}

		_exit(0);
	}
	while (1) /* wait for new netns process */
	{
		r = waitpid(p, &status, 0);
		if (r == -1 && errno == EINTR) {
			continue;
		}
		else if (r == p) {
			break;
		}
		else {
			printf("waitpid(%d) error: %s\n", p, strerror(errno));
			return -1;
		}
	}
	if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
		return 0;

	return -1;
}

int netns_setup()
{
	char ifname[16];
	char *gateway;
	char *dev;
	int r;

	if (g_newnet.kind == RTNL_KIND_INVALID)
		return -1;

	/* new iface name is pid, renamed to match root device after namespace transit */
	snprintf(ifname, sizeof(ifname), "%d", getpid());

	/* create new interface in root namespace */
	switch (g_newnet.kind)
	{
	case RTNL_KIND_IPVLAN:
		/* create ipvlan device */
		r = eslib_rtnetlink_linknew(ifname, "ipvlan", g_newnet.dev);
		if (r) {
			printf("linknew(%s, ipvlan, %s)\n", ifname, g_newnet.dev);
			(r == 1) ? printf("nack\n") : printf("error\n");
			return -1;
		}
		r = eslib_rtnetlink_linksetns(ifname, g_initpid);
		if (r) {
			printf("couldn't setns %s \n", ifname);
			(r == 1) ? printf("nack\n") : printf("error\n");
			eslib_rtnetlink_linkdel(ifname);
			return -1;
		}

		dev = g_newnet.dev;
		if (*dev == '\0')
			return -1;

		/* set gateway */
		gateway = eslib_rtnetlink_getgateway(dev);
		if (gateway == NULL) {
			printf("couldn't get link gateway\n");
			return -1;
		}
		memset(g_newnet.gateway, 0, sizeof(g_newnet.gateway));
		strncpy(g_newnet.gateway, gateway, sizeof(g_newnet.gateway)-1);

		break;

	case RTNL_KIND_VETHBR:
		printf("todo\n");
		return -1;
		break;
	default:
		break;
	}

	if (netns_enter_and_config(ifname, g_initpid)) {
		printf("could not configure new net namespace\n");
		return -1;
	}
	return 0;
}

/*
 *  read current firewall configuration so we can copy it to new namespace
 *  assumes firewall save program writes to stdout.
 */
int netns_save_firewall(char *buf, int size)
{
	int ipc[2];
	char *argv[] = { "fwsave", FIREWALL_SAVE, NULL };
	if (buf == NULL || size <= 0)
		return -1;
	memset(buf, 0, size);

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, ipc)) {
		printf("socketpair: %s\n", strerror(errno));
		return -1;
	}
	if (do_exec(FIREWALL_PROG, argv, ipc, NULL, 0)) {
		printf("exec(%s) failed\n", FIREWALL_PROG);
		goto close_err;
	}
	close(ipc[1]);
	while(1)
	{
		int r = read(ipc[0], buf, size);
		if (r == size) {
			printf("filter too big, size=%d\n", size);
			goto close_err;
		}
		else if (r == -1 && (errno == EAGAIN || errno == EINTR)) {
			continue;
		}
		else if (r <= 0) {
			printf("read error\n");
			goto close_err;
		}
		else {
			close(ipc[0]);
			return r;
		}
	}
close_err:
	close(ipc[0]);
	return -1;
}

/*
 * restore firewall rules, assumes firewall program's restore reads from stdin.
 */
int netns_restore_firewall(char *buf, int size)
{
	int ipc[2];
	char *argv[] = { "fwrestore", FIREWALL_RESTORE, NULL };

	if (buf == NULL || size <= 0)
		return -1;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, ipc)) {
		printf("socketpair: %s\n", strerror(errno));
		return -1;
	}
	if (do_exec(FIREWALL_PROG, argv, ipc, buf, size)) {
		printf("exec(%s) failed\n", FIREWALL_PROG);
		close(ipc[0]);
		close(ipc[1]);
		return -1;
	}
	close(ipc[0]);
	close(ipc[1]);
	return 0;
}

/*
 *  execute firewall program to install additional rules.
 *  TODO
 */
int netns_exec_firewall(char *args)
{
	return (int)args;
}
