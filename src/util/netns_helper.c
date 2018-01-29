/* (c) 2015 Michael R. Tirado -- GPLv3, GNU General Public License, version 3.
 * contact: mtirado418@gmail.com
 */
#define _GNU_SOURCE
#include <linux/unistd.h>
#include <stdio.h>
#include <errno.h>
#include <sched.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <malloc.h>
#include <linux/rtnetlink.h>
#include <linux/if_link.h>
#include <stdlib.h>
#include <time.h>
#include <limits.h>
#include "../eslib/eslib.h"
#include "../eslib/eslib_rtnetlink.h"
#include "../eslib/eslib_fortify.h"
#include "../pod.h"
#include "../misc.h"

/* external globals in jettison.c */
extern uid_t g_ruid;
extern gid_t g_rgid;
extern struct newnet_param g_newnet; /* setup in pod.c */
extern struct user_privs   g_privs;  /* setup in jettison.c */
extern char **environ;
extern char g_cwd[MAX_SYSTEMPATH];
extern pid_t g_mainpid;
extern char g_chroot_path[MAX_SYSTEMPATH];

static int netns_lo_config()
{
	int r;
	r = eslib_rtnetlink_linksetup("lo");
	if (r) {
		printf("couldn't set lo up\n");
		(r > 0) ? printf("nack: %s\n",strerror(r)):printf("error\n");
		return -1;
	}
	return 0;
}

static int netns_vlan_config(char *ifname, char *gateway)
{
	int r;
	if (!ifname || !gateway) {
		printf("invalid vlan_config params\n");
		return -1;
	}

	/* set loopback up */
	r = eslib_rtnetlink_linksetup("lo");
	if (r) {
		printf("couldn't set lo up\n");
		(r > 0) ? printf("nack: %s\n",strerror(r)):printf("error\n");
		return -1;
	}
	/* set new link name*/
	r = eslib_rtnetlink_linksetname(ifname, NEWNET_LINK_NAME);
	if (r) {
		printf("couldn't set interface name\n");
		(r > 0) ? printf("nack: %s\n",strerror(r)):printf("error\n");
		return -1;
	}
	/* set up */
	r = eslib_rtnetlink_linksetup(NEWNET_LINK_NAME);
	if (r) {
		printf("couldn't set %s up\n", ifname);
		(r > 0) ? printf("nack: %s\n",strerror(r)):printf("error\n");
		eslib_rtnetlink_linkdel(ifname);
		return -1;
	}
	/* set address */
	r = eslib_rtnetlink_linkaddr(NEWNET_LINK_NAME, g_newnet.addr, g_newnet.netmask);
	if (r) {
		printf("couldn't add address(%s/%d) to iface %s\n",
				g_newnet.addr, g_newnet.netmask, NEWNET_LINK_NAME);
		(r > 0) ? printf("nack: %s\n",strerror(r)):printf("error\n");
		eslib_rtnetlink_linkdel(ifname);
		return -1;
	}
	/* set gateway */
	printf("\r\n---------------------------------------------------------\r\n");
	printf("dev/addr/mask: %s %s %d\r\n",
			NEWNET_LINK_NAME, g_newnet.addr, g_newnet.netmask);
	printf("---------------------------------------------------------\r\n");
	r = eslib_rtnetlink_setgateway(NEWNET_LINK_NAME, g_newnet.gateway);
	if (r) {
		printf("couldn't set gateway for iface %s\n", NEWNET_LINK_NAME);
		(r > 0) ? printf("nack: %s\n",strerror(r)):printf("error\n");
		eslib_rtnetlink_linkdel(ifname);
		return -1;
	}
	return 0;
}

static int netns_enter_proc(char *pid)
{
	char path[MAX_SYSTEMPATH];
	int nsfd;
	int retries = 15;

	if (es_sprintf(path, sizeof(path), NULL, "/proc/%s/ns/net", pid))
		return -1;

	while (1)
	{
		nsfd = open(path, O_RDONLY);
		if (nsfd == -1) {
			if (--retries < 0) {
				printf("netns open(%s): %s\n", path, strerror(errno));
				return -1;
			}
			usleep(100000);
		}
		else {
			break;
		}
	}
	if (setns(nsfd, CLONE_NEWNET)) {
		printf("setns(newnet): %s\n", strerror(errno));
		close(nsfd);
		return -1;
	}
	close(nsfd);
	return 0;
}

/*
 * enter new namespace and configure using g_newnet global
 */
static int netns_enter_and_config(char *ifname)
{
	/* enter new namespace */
	if (setns(g_newnet.new_ns, CLONE_NEWNET)) {
		printf("set new_ns: %s\n", strerror(errno));
		return -1;
	}

	/* setup type specific devices */
	switch (g_newnet.kind)
	{
	case ESRTNL_KIND_UNKNOWN:
		break;
	case ESRTNL_KIND_LOOP:
		if (netns_lo_config()) {
			printf("loopback config failed\n");
			return -1;
		}
		break;
	case ESRTNL_KIND_IPVLAN:
	case ESRTNL_KIND_MACVLAN:
		if (netns_vlan_config(ifname, g_newnet.gateway)) {
			printf("vlan config failed\n");
			return -1;
		}
		break;
	default:
		printf("bad net interface kind: %d\n", g_newnet.kind);
		return -1;
		break;
	}

	return 0;
}

/* waits for ipvlan count lock */
static int ipvlan_wrlock()
{
	struct flock fl;
	int r;
	int fd;

	errno = 0;
	memset(&fl, 0, sizeof(fl));
	fl.l_type   = F_WRLCK;
	fl.l_whence = SEEK_SET;

	r = eslib_file_exists(IPVLAN_COUNT_LOCKFILE);
	if (r == -1) {
		return -1;
	}
	else if (r == 0) {
		if (eslib_file_mkfile(IPVLAN_COUNT_LOCKFILE, 0755)) {
			return -1;
		}
	}

	fd = open(IPVLAN_COUNT_LOCKFILE, O_RDWR);
	if (fd == -1) {
		printf("open lock: %s\n", strerror(errno));
		return -1;
	}
	if (fcntl(fd, F_SETLKW, &fl)) {
		printf("fcntl(F_SETLKW): %s\n", strerror(errno));
		close(fd);
		return -1;
	}

	return fd;
}

/* track which namespaces have been traversed */
#define NSNODE_NAMESZ 32
struct netns_node {
	struct netns_node *next;
	char name[NSNODE_NAMESZ];
};
struct netns_node *nsnode_list;
static int find_nsnode(char *name)
{
	struct netns_node *n = nsnode_list;
	while (n)
	{
		if (strncmp(name, n->name, sizeof(n->name)) == 0)
			return 1;
		n = n->next;
	}
	return 0;
}

/* increment output counter for each ipvlan interface kind */
int decode_count_ipvlan(struct rtnl_decode_io *dio, void *msg, unsigned int msgsize,
		    struct rtattr *tbl[], unsigned int tblcount)
{
	struct ifinfomsg *ifmsg = msg;
	if (ifmsg == NULL || tbl == NULL)
		return -1;
	if (rtnl_decode_check(dio, 0, sizeof(int), RTM_GETLINK, msgsize, tblcount))
		return -1;

	if (tbl[IFLA_LINKINFO]) {
		struct rtattr *linkinfo = tbl[IFLA_LINKINFO];
		struct rtattr *infokind;
		char *kind;
		infokind = rtnetlink_get_attr(RTA_DATA(linkinfo),
				RTA_PAYLOAD(linkinfo), IFLA_INFO_KIND);
		if (infokind == NULL) {
			printf("couldn't find link kind\n");
			return -1;
		}
		kind = RTA_DATA(infokind);
		if (kind != NULL) {
			if (strncmp(kind, "ipvlan", RTA_PAYLOAD(infokind)) == 0) {
				*((int *)dio->out) += 1;
			}
			else if (strncmp(kind, "macvlan", RTA_PAYLOAD(infokind)) == 0) {
				*((int *)dio->out) += 1;
			}
		}
	}

	return 0;
}
/* return number of existing ipvlan interfaces */
int rtnetlink_countipvlan()
{
	struct rtnl_decode_io dio;
	int out = 0;
	memset(&dio, 0, sizeof(dio));
	rtnl_decode_setcallback(&dio, decode_count_ipvlan);
	rtnl_decode_setoutput(&dio, &out, sizeof(out));
	if (eslib_rtnetlink_dump(&dio, RTM_GETLINK)) {
		printf("dump request failed\n");
		return -1;
	}
	return out;
}

/* return number of virtual devices like ipvlan and macvlan, which are attached
 * to a device in root network namespace, and have independent addresses on network.
 * we will consult a config file to determine a particular users net resource limits.
 *
 * notes: caller is responsible for unlocking lockfd when done.
 */
int netns_count_ipvlan_devices(int *lockfd)
{
	char path[MAX_SYSTEMPATH];
	struct dirent *dent;
	DIR *dir;
	unsigned int count_ret = 0;
	int fd;

	if (lockfd == NULL)
		return -1;
	nsnode_list = NULL;
	*lockfd = -1;

	while (1)
	{
		fd = ipvlan_wrlock();
		if (fd == -1 && errno != EINTR)
			return -1;
		else if (fd != -1)
			break;
	}

	setuid(g_ruid);
	setgid(g_rgid);
	dir = opendir("/proc");
	if (dir == NULL) {
		printf("error opening /proc: %s\n", strerror(errno));
		close(fd);
		return -1;
	}
	/* count ipvlan devices in all of users /proc net namespaces */
	while (1)
	{
		struct netns_node bufnode;
		struct netns_node *n;
		int skip = 0;
		int i = 0;
		int r;
		errno = 0;

		/* find a process-id numbered directory entry */
		dent = readdir(dir);
		if (dent == NULL && errno == 0) {
			break;
		}else if (dent == NULL) {
			printf("readdir: %s\n", strerror(errno));
			goto free_err;
		}
		for (i = 0; dent->d_name[i] != '\0'; ++i)
		{
			if (dent->d_name[i] < '0' || dent->d_name[i] > '9') {
				/* not a process directory */
				skip = 1;
				break;
			}
		}
		if (skip) {
			continue;
		}

		/* open processes namespace */
		if (es_sprintf(path, sizeof(path),NULL,"/proc/%s/ns/net", dent->d_name))
			goto free_err;
		r = open(path, O_RDONLY);
		if (r == -1 && errno == EACCES) {
			close(r);
			continue; /* we don't own it */
		}
		else if (r == -1) {
			printf("open(%s): %s\n", path, strerror(errno));
			close(r);
			goto free_err;
		}
		close(r);

		/* check if netns has been counted already */
		memset(&bufnode, 0, sizeof(bufnode));
		errno = 0;
		r = readlink(path, bufnode.name, NSNODE_NAMESZ-1);
		if (r >= NSNODE_NAMESZ-1 || r <= 0) {
			printf("readlink: %s\n", strerror(errno));
			goto free_err;
		}
		if (find_nsnode(bufnode.name))
			continue;

		/* enter namespace, and count interfaces */
		if (netns_enter_proc(dent->d_name)) {
			printf("netns_enter(%s): %s\n", dent->d_name, strerror(errno));
			goto free_err;
		}
		r = rtnetlink_countipvlan();
		if (r < 0) {
			goto free_err;
		}
		if (count_ret + (unsigned int)r >= INT_MAX
				|| count_ret + (unsigned int) r < count_ret)
			goto free_err;
		/* mark as counted */
		n = malloc(sizeof(struct netns_node));
		if (n == NULL) {
			goto free_err;
		}
		memcpy(n, &bufnode, sizeof(bufnode));
		n->next = nsnode_list;
		nsnode_list = n;

		count_ret += (unsigned int)r;
	}
	setuid(0);
	setgid(0);
	/* return to original netns */
	if (setns(g_newnet.root_ns, CLONE_NEWNET)) {
		printf("setns(root_ns): %s\n", strerror(errno));
		goto free_err;
	}
	while (nsnode_list)
	{
		struct netns_node *n = nsnode_list->next;
		free(nsnode_list);
		nsnode_list = n;
	}
	closedir(dir);
	*lockfd = fd;
	return (int)count_ret;

free_err:
	closedir(dir);
	close(fd);
	while (nsnode_list)
	{
		struct netns_node *n = nsnode_list->next;
		free(nsnode_list);
		nsnode_list = n;
	}
	return -1;
}

int netns_setup()
{
	char path[MAX_SYSTEMPATH];
	char ifname[16];
	char *gateway;
	int r;
	int lockfd = -1;
	int count = 0;

	if (g_newnet.kind == ESRTNL_KIND_INVALID)
		return -1;

	/* open root namespace fd */
	if (es_sprintf(path, sizeof(path), NULL, "/proc/%d/ns/net", getpid()))
		return -1;
	g_newnet.root_ns = open(path, O_RDONLY|O_CLOEXEC);
	if (g_newnet.root_ns == -1) {
		printf("root netns fd open: %s\n", strerror(errno));
		return -1;
	}

	/* create new namespace */
	if (unshare(CLONE_NEWNET)) {
		printf("unshare(CLONE_NEWNET): %s\n", strerror(errno));
		close(g_newnet.root_ns);
		return -1;
	}
	/* open new namespace fd */
	if (es_sprintf(path, sizeof(path), NULL, "/proc/%d/ns/net", getpid()))
		return -1;
	g_newnet.new_ns = open(path, O_RDONLY|O_CLOEXEC);
	if (g_newnet.new_ns == -1) {
		printf("new_ns fd open: %s\n", strerror(errno));
		close(g_newnet.root_ns);
		return -1;
	}
	/* back to root namespace */
	if (setns(g_newnet.root_ns, CLONE_NEWNET)) {
		printf("set root_ns : %s\n", strerror(errno));
		close(g_newnet.root_ns);
		close(g_newnet.new_ns);
		return -1;
	}

	/* new name is t<pid>, renamed after namespace transit */
	if (es_sprintf(ifname, sizeof(ifname), NULL, "t%d", getpid()))
		return -1;

	/* create new interface and move to new namespace */
	switch (g_newnet.kind)
	{
	case ESRTNL_KIND_IPVLAN:
	case ESRTNL_KIND_MACVLAN:

		/* check ipvlan count */
		count = netns_count_ipvlan_devices(&lockfd);
		if (count < 0) {
			goto netns_err;
		}
		/* authorize ip/macvlan parameters */
		if ((unsigned int)count >= g_privs.ipvlan_limit) {
			printf("user reached ipvlan limit(%d)\n", g_privs.ipvlan_limit);
			close(lockfd);
			goto netns_err;
		}
		else if (g_privs.ipvlan_limit == 0) {
			printf("ip/macvlan permission error\n");
			close(lockfd);
			goto netns_err;
		}
		/* create ipvlan/macvlan device */
		if (g_newnet.kind == ESRTNL_KIND_IPVLAN)
			r = eslib_rtnetlink_linknew(ifname, "ipvlan", NEWNET_LINK_NAME);
		else
			r = eslib_rtnetlink_linknew(ifname, "macvlan", NEWNET_LINK_NAME);
		if (r) {
			printf("linknew(%s, xxxvlan, %s)\r\n", ifname, NEWNET_LINK_NAME);
			(r > 0) ? printf("nack: %s\n",strerror(r)):printf("error\n");
			if (r == EBUSY) {
				printf("hint: vlan type must match for master device\n");
				printf("try swapping macvlan <-> ipvlan option.\n");
			}
			close(lockfd);
			goto netns_err;
		}
		if (g_newnet.kind == ESRTNL_KIND_MACVLAN &&
				strncmp(g_newnet.hwaddr, "**:**:**:**:**:**", 18)) {
			/* set mac addr */
			r = eslib_rtnetlink_linkhwaddr(ifname, g_newnet.hwaddr);
			if (r) {
				printf("couldn't set mac address\n");
				(r > 0)?printf("nack:%s\n",strerror(r)):printf("err\n");
				goto ipvlan_err;
			}
		}
		r = eslib_rtnetlink_linksetns(ifname, (uint32_t)g_newnet.new_ns, 0);
		if (r) {
			printf("temp link(%s) setns failed\n", ifname);
			(r > 0) ? printf("nack: %s\n",strerror(r)):printf("error\n");
			goto ipvlan_err;
		}

		/* set gateway */
		gateway = eslib_rtnetlink_getgateway(NEWNET_LINK_NAME);
		if (gateway == NULL) {
			printf("couldn't get link gateway\n");
			goto ipvlan_err;
		}
		if (es_strcopy(g_newnet.gateway, gateway, sizeof(g_newnet.gateway),NULL))
			goto ipvlan_err;
		close(lockfd);
		break;

	case ESRTNL_KIND_VETHBR:
		printf("todo\n");
		goto netns_err;
		break;
	case ESRTNL_KIND_LOOP:
	case ESRTNL_KIND_UNKNOWN:
		break;

	default:
		printf("netns error\n");
		goto netns_err;
	}

	if (netns_enter_and_config(ifname)) {
		printf("could not configure new net namespace\n");
		goto netns_err;
	}

	close(g_newnet.root_ns);
	close(g_newnet.new_ns);
	return 0;

netns_err:
	close(g_newnet.root_ns);
	close(g_newnet.new_ns);
	return -1;

ipvlan_err:
	close(g_newnet.root_ns);
	close(g_newnet.new_ns);
	eslib_rtnetlink_linkdel(ifname);
	close(lockfd);
	return -1;
}

