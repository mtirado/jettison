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
#include <dirent.h>
#include <malloc.h>
#include <linux/rtnetlink.h>
#include <linux/if_link.h>
#include "../eslib/eslib.h"
#include "../eslib/eslib_rtnetlink.h"
#include "../pod.h"

/* reimplementing these in eslib would take quite a bit of time and
 * less flexible than using admin's program of choice, we can set pod
 * specific rules in /etc/jettison/net/<prog>/netfilter or elsewhere...
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

#ifndef IPVLAN_COUNT_LOCKFILE
	#define IPVLAN_COUNT_LOCKFILE "/var/lock/jettison/ipvlan_counter"
#endif
#ifndef JETTISON_NETPRIVS
	#define JETTISON_NETPRIVS "/etc/jettison/net/users/"
#endif

/* TODO remove */
#define TEST_IPVLAN_LIMIT 5

/* external globals in jettison.c */
extern uid_t g_ruid;
extern gid_t g_rgid;
extern pid_t g_initpid;
extern pid_t g_mainpid;
extern struct newnet_param g_newnet; /* setup by pod.c */
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
	printf("\r\n---------------------------------------------------------\r\n");
	printf("dev/addr/mask: %s %s %d\r\n", dev, g_newnet.addr, g_newnet.netmask);
	printf("---------------------------------------------------------\r\n");
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
	int std;
	FILE *stdo;
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
		stdo = stdout;
		if (std_io) {
			std = dup(STDOUT_FILENO);
			stdo = fdopen(std, "w");
			if (stdo == NULL
				|| dup2(std_io[1], STDIN_FILENO) != STDIN_FILENO
				|| dup2(std_io[1], STDOUT_FILENO) != STDOUT_FILENO
				|| dup2(std_io[1], STDERR_FILENO) != STDERR_FILENO) {
				printf("stdio replacement failure\n");
				_exit(-1);
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
			fprintf(stdo, "capset: %s\r\n", strerror(errno));
			fprintf(stdo, "cap version: %p\r\n", (void *)hdr.version);
			fprintf(stdo, "pid: %d\r\n", hdr.pid);
			_exit(-1);
		}
		if (execve(path, argv, environ)) {
			fprintf(stdo, "execve: %s\n", strerror(errno));
			_exit(-1);
		}
		_exit(-1);
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

static int netns_enter(char *pid)
{
	char path[MAX_SYSTEMPATH];
	int nsfd;
	int retries = 15;
	char buf[64];
	int r;
	snprintf(path, sizeof(path), "/proc/%s/ns/net", pid);
	memset(buf, 0, sizeof(buf));
	r = readlink(path, buf, sizeof(buf)-1);
	if (r >= (int)sizeof(buf)-1 || r <= 0) {
		printf("readlink: %s\n", strerror(errno));
		return -1;
	}
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
static int netns_enter_and_config(char *ifname, char *targetpid)
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
		setuid(g_ruid);
		setgid(g_rgid);
		if (netns_enter(targetpid))
			_exit(-1);
		setuid(0);
		setgid(0);
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
			printf("read error(%d)\n", r);
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
 *  TODO  ^^
 */
int netns_exec_firewall(char *args)
{
	return (int)args;
}

/* waits for ipvlan count lock */
static int ipvlan_wrlock()
{
	struct flock fl;
	int r;
	int fd;
	memset(&fl, 0, sizeof(fl));
	fl.l_type   = F_WRLCK;
	fl.l_whence = SEEK_SET;

	r = eslib_file_exists(IPVLAN_COUNT_LOCKFILE);
	if (r == -1) {
		return -1;
	}
	else if (r == 0) {
		if (eslib_file_mkfile(IPVLAN_COUNT_LOCKFILE, 0755, 0)) {
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
 * XXX only counts ipvlan at the moment, but should count macvlan when implemented.
 */
int netns_count_ipvlan_devices(int *lockfd)
{
	char path[MAX_SYSTEMPATH];
	struct dirent *dent;
	DIR *dir;
	unsigned int count_ret = 0;
	int fd;
	int main_netns;

	if (lockfd == NULL)
		return -1;
	nsnode_list = NULL;
	*lockfd = -1;

	/* handle race condition using file lock */
	while (1)
	{
		errno = 0;
		fd = ipvlan_wrlock();
		if (fd == -1 && errno != EINTR)
			return -1;
		else if (fd != -1)
			break;
	}

	/* hold on to main net namespace */
	snprintf(path, sizeof(path), "/proc/%d/ns/net", getpid());
	main_netns = open(path, O_RDONLY|O_CLOEXEC);
	if (main_netns == -1) {
		printf("main netns open: %s\n", strerror(errno));
		return -1;
	}

	/* only access users namespaces */
	setuid(g_ruid);
	setgid(g_rgid);

	dir = opendir("/proc");
	if (dir == NULL) {
		printf("error opening /proc: %s\n", strerror(errno));
		close(main_netns);
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
		r = snprintf(path, sizeof(path), "/proc/%s/ns/net", dent->d_name);
		if ((unsigned int)r >= sizeof(path) || r <= 0) {
			goto free_err;
		}
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
		if (netns_enter(dent->d_name)) {
			printf("netns_enter(%s): %s\n", dent->d_name, strerror(errno));
			goto free_err;
		}
		r = rtnetlink_countipvlan();
		if (r < 0) {
			goto free_err;
		}

		/* mark as counted */
		n = malloc(sizeof(struct netns_node));
		if (n == NULL) {
			goto free_err;
		}
		memcpy(n, &bufnode, sizeof(bufnode));
		n->next = nsnode_list;
		nsnode_list = n;

		count_ret += r;
	}

	/* return to original netns */
	if (setns(main_netns, CLONE_NEWNET)) {
		printf("netns_enter(%s): %s\n", path, strerror(errno));
		goto free_err;
	}
	while (nsnode_list)
	{
		struct netns_node *n = nsnode_list->next;
		free(nsnode_list);
		nsnode_list = n;
	}
	close(main_netns);
	closedir(dir);
	setuid(0);
	setgid(0);
	*lockfd = fd;
	return count_ret;

free_err:
	close(main_netns);
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
	char ifname[16];
	char targetpid[32];
	char *gateway;
	char *dev;
	int r;
	int lockfd = -1;
	int count = 0;

	if (g_newnet.kind == RTNL_KIND_INVALID)
		return -1;

	/* new name is t<pid>, renamed to match root device after namespace transit */
	snprintf(ifname, sizeof(ifname), "t%d", getpid());

	/* create new interface and move to new namespace */
	switch (g_newnet.kind)
	{
	case RTNL_KIND_IPVLAN:

		/* check ipvlan count */
		count = netns_count_ipvlan_devices(&lockfd);
		if (count < 0)
			return -1;
		if (count >= TEST_IPVLAN_LIMIT) {
			printf("ipvlan limit(%d) reached\n", TEST_IPVLAN_LIMIT);
			close(lockfd);
			return -1;
		}
		/* create ipvlan device */
		r = eslib_rtnetlink_linknew(ifname, "ipvlan", g_newnet.dev);
		if (r) {
			printf("linknew(%s, ipvlan, %s)\n", ifname, g_newnet.dev);
			(r == 1) ? printf("nack\n") : printf("error\n");
			close(lockfd);
			return -1;
		}
		r = eslib_rtnetlink_linksetns(ifname, g_initpid);
		if (r) {
			printf("temp link(%s) setns failed\n", ifname);
			(r == 1) ? printf("nack\n") : printf("error\n");
			goto ipvlan_err;
		}
		dev = g_newnet.dev;
		if (*dev == '\0')
			goto ipvlan_err;

		/* set gateway */
		gateway = eslib_rtnetlink_getgateway(dev);
		if (gateway == NULL) {
			printf("couldn't get link gateway\n");
			goto ipvlan_err;
		}
		memset(g_newnet.gateway, 0, sizeof(g_newnet.gateway));
		strncpy(g_newnet.gateway, gateway, sizeof(g_newnet.gateway)-1);
		close(lockfd);
		break;

	case RTNL_KIND_VETHBR:
		printf("todo\n");
		return -1;
		break;
	default:
		break;
	}
	snprintf(targetpid, sizeof(targetpid), "%d", g_initpid);
	if (netns_enter_and_config(ifname, targetpid)) {
		printf("could not configure new net namespace\n");
		return -1;
	}
	return 0;

ipvlan_err:
	eslib_rtnetlink_linkdel(ifname);
	close(lockfd);
	return -1;
}

