/* (c) 2015 Michael R. Tirado -- GPLv3, GNU General Public License, version 3.
 * contact: mtirado418@gmail.com
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <sched.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <string.h>
#include "../eslib/eslib.h"
#include "../eslib/eslib_rtnetlink.h"
#include "../pod.h"

/* external globals in jettison.c */
extern uid_t g_ruid;
extern gid_t g_rgid;
extern pid_t g_initpid;
extern struct newnet_param g_newnet;

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

/*
 * enter new namespace and hookup with the root namespace device
 */
static int netns_enter_and_config(char *ifname, pid_t target)
{
	pid_t p;
	int status;
	int r;

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
	else
		return -1;
}

int netns_setup()
{
	char ifname[16];
	char *gateway;
	char *dev;
	int r;

	if (g_newnet.kind == RTNL_KIND_INVALID)
		return 0;

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
