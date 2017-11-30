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
#include "capability.h"
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <malloc.h>
#include <linux/rtnetlink.h>
#include <linux/if_link.h>
#include <stdlib.h>
#include <time.h>
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
extern int g_lognet;
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
 * XXX only counts ipvlan at the moment, but should count macvlan when implemented.
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
	setuid(0);
	setgid(0);
	*lockfd = fd;
	return count_ret;

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

static int fortify_netlog(char *chroot_path, gid_t log_group, char *logdir)
{
	struct path_node node;
	int cap_e[NUM_OF_CAPS];
	int cap_p[NUM_OF_CAPS];
	int cap_i[NUM_OF_CAPS];
	memset(&cap_e, 0, sizeof(cap_e));
	memset(&cap_p, 0, sizeof(cap_p));
	memset(&cap_i, 0, sizeof(cap_i));
	cap_p[CAP_SETGID]  = 1;
	cap_e[CAP_SETGID]  = 1;
	cap_p[CAP_SETUID]  = 1;
	cap_e[CAP_SETUID]  = 1;
	cap_p[CAP_NET_RAW] = 1;
	cap_i[CAP_NET_RAW] = 1;

	memset(&node, 0, sizeof(node));
	node.mntflags = MS_RDONLY|MS_NODEV|MS_UNBINDABLE|MS_NOSUID;

	if (eslib_fortify_prepare(chroot_path, 0)) {
		printf("fortify failed\n");
		return -1;
	}

	if (eslib_fortify_install_file(chroot_path, NETLOG_PROG, node.mntflags,
				ESLIB_BIND_CREATE | ESLIB_BIND_PRIVATE))
		goto fail;
	if (eslib_fortify_install_file(chroot_path, "/lib", node.mntflags,
				ESLIB_BIND_CREATE | ESLIB_BIND_PRIVATE))
		goto fail;
	if (eslib_fortify_install_file(chroot_path, "/usr/lib", node.mntflags,
				ESLIB_BIND_CREATE | ESLIB_BIND_PRIVATE))
		goto fail;

	/* bind log directory TODO helper function for this, warp_file? */
	node.mntflags = MS_NOEXEC|MS_NODEV|MS_NOSUID;
	if (es_strcopy(node.src, logdir, MAX_SYSTEMPATH, NULL))
		goto fail;
	if (es_sprintf(node.dest, MAX_SYSTEMPATH, NULL, "%s/%s", chroot_path, "logdir"))
		goto fail;
	eslib_file_mkdirpath(node.dest, 0770);
	if (pathnode_bind(&node))
		goto fail;

	/* TODO syscall filter  with strict mode */
	if (eslib_fortify(chroot_path,
			  0,log_group,
			  NULL,
			  0,cap_e,cap_p,cap_i,
			  ESLIB_FORTIFY_IGNORE_CAP_BLACKLIST
			 |ESLIB_FORTIFY_SHARE_NET)) {
		printf("fortify failed\n");
		return -1;
	}
	return 0;
fail:
	printf("fortify_netlog: failed to bind file\n");
	return -1;
}

static int create_logdir(char *buf, unsigned int size, gid_t log_gid)
{
	char hexstr[17];
	struct timespec t;
	char *filename;
	int r;

retry:
	if (buf == NULL || size == 0 || size > MAX_SYSTEMPATH)
		return -1;

	clock_gettime(CLOCK_MONOTONIC_RAW, &t);
	filename = eslib_file_getname(g_chroot_path);
	if (filename == NULL)
		return -1;

	if (randhex(hexstr, 16, 0x0f0f0f0f+g_mainpid+t.tv_nsec+t.tv_sec, 1350))
		return -1;
	hexstr[16] = '\0';

	if (es_sprintf(buf, size, NULL, "%s/%s-%s.netlog", g_cwd, filename, hexstr))
		return -1;
	if (eslib_file_path_check(buf)) {
		printf("bad logdir: %s\n", buf);
		return -1;
	}
	setuid(g_ruid);
	setgid(g_rgid);
	r = mkdir(buf, 0750);
	if (r && errno == EEXIST) {
		printf("improbable name collision in --lognet directory: %s\n", buf);
		usleep(500000);
		goto retry;
	}
	else if (r) {
		printf("mkdir(%s): %s\n", buf, strerror(errno));
		return -1;
	}

	if (chmod(buf, 0750)) {
		printf("chmod: %s\n", strerror(errno));
		return -1;
	}
	if (chown(buf, g_ruid, log_gid)) {
		printf("chown: %s\n", strerror(errno));
		return -1;
	}
	setuid(0);
	setgid(0);
	return 0;
}

/* returns new pid, or -1 on error */
static pid_t do_netlog_exec(char *argv[])
{
	char chroot_path[MAX_SYSTEMPATH];
	char logpath[MAX_SYSTEMPATH];
	gid_t log_group;
	pid_t p;
	int status;
	int r, i;
	int notify[2];

	if (!argv)
		return -1;
	if (strnlen(NETLOG_PROG, MAX_SYSTEMPATH) >= MAX_SYSTEMPATH)
		return -1;

	log_group = get_group_id(NETLOG_GROUP);
	if ((int)log_group == -1) {
		printf("add log group to group file, default is 'nobody'\n");
		return -1;
	}

	if (es_sprintf(chroot_path, sizeof(chroot_path), NULL, "%s/.netlog", POD_PATH))
		return -1;
	if (eslib_file_path_check(chroot_path)) {
		printf("bad chroot_path: %s\n", chroot_path);
		return -1;
	}
	if (mkdir(chroot_path, 0775) && errno != EEXIST) {
		printf("minipod mkdir(%s): %s\n", chroot_path, strerror(errno));
		return -1;
	}
	/* directory logs are written to*/
	if (create_logdir(logpath, sizeof(logpath), log_group))
		return -1;
	printf("netlog directory: %s\n", logpath);

	if (pipe2(notify, O_CLOEXEC)) {
		printf("pipe: %s\n", strerror(errno));
		return -1;
	}

	p = fork();
	if (p == -1) {
		printf("fork(): %s\n", strerror(errno));
		return -1;
	}
	else if (p == 0) {
		const char ack = 'K';
		int fdcount;
		int *fdlist;
		int i;

		if (setns(g_newnet.new_ns, CLONE_NEWNET)) {
			printf("set new_ns: %s\n", strerror(errno));
			_exit(-1);
		}
		/*
		 * close all fd's
		 * */
		close(g_newnet.root_ns);
		close(g_newnet.new_ns);
		close(notify[0]);
		fdcount = eslib_proc_alloc_fdlist(getpid(), &fdlist);
		if (fdcount == -1) {
			printf("fdlist error\n");
			_exit(-1);
		}
		for (i = 0; i < fdcount; ++i)
		{
			if (fdlist[i] != STDIN_FILENO
					&& fdlist[i] != STDOUT_FILENO
					&& fdlist[i] != STDERR_FILENO
					&& fdlist[i] != notify[1]) {
				close(fdlist[i]);
			}
		}
		free(fdlist);

		if (fortify_netlog(chroot_path, log_group, logpath)) {
			printf("fortify_netlog failed\n");
			_exit(-1);
		}
		if (setuid(g_ruid))
			_exit(-1);
		if (seteuid(0)) /* inherit cap */
			_exit(-1);

		if (write(notify[1], &ack, 1) != 1) {
			printf("write: %s\n", strerror(errno));
			_exit(-1);
		}
		close(notify[1]);

		if (execve(NETLOG_PROG, argv, environ)) {
			printf("execve: %s\n", strerror(errno));
		}
		_exit(-1);
	}
	close(notify[1]);
	while (1)
	{
		char rd;
		r = read(notify[0], &rd, 1);
		if (r == -1 && (errno == EAGAIN || errno == EINTR))
			continue;
		else if (r == 1 && rd == 'K')
			break;
		else
			return -1;
	}
	close(notify[0]);
	i = 0;
	/* detect early failures */
	while(++i <= 30)
	{
		pid_t pr;
		usleep(10000);
		pr = waitpid(p, &status, WNOHANG);
		if (pr) {
			printf("unxpected netlog waitpid\n");
			return -1;
		}
	}

	return p;
}

static pid_t setup_netlog()
{
	pid_t p;
	/* tcpdump specific, we could write our own packet logger someday */
	char *args[10];
	char arg0[]      = "netlog";
	char arg1[]      = "-p"; /* don't set promiscuous mode */
	char arg2[]      = "-w";
	char arg_size[]  = "-C";
	char arg_count[] = "-W";
	char str_filename[32];
	char str_size[32];
	char str_count[32];

	if (g_newnet.kind != ESRTNL_KIND_IPVLAN && g_newnet.kind != ESRTNL_KIND_MACVLAN)
		return -1;

	if (es_sprintf(str_size, sizeof(str_size), NULL, "%d", g_newnet.log_filesize))
		return -1;
	if (es_sprintf(str_count, sizeof(str_count), NULL, "%d", g_newnet.log_count))
		return -1;
	if (es_strcopy(str_filename, "logdir/netlog.pcap", sizeof(str_filename), NULL))
		return -1;

	if (g_newnet.log_filesize < 0)
		return -1;

	args[0] = arg0;
	args[1] = arg1;
	args[2] = arg2;
	args[3] = str_filename;

	if (g_newnet.log_filesize == 0) {
		args[4] = NULL;
	}
	else {
		/* single constrained logfile */
		args[4] = arg_size;
		args[5] = str_size;
		if (g_newnet.log_count >= 2 ) {
			args[6] = arg_count;
			args[7] = str_count;
			args[8] = NULL;
		}
		else {
			args[6] = NULL;
		}
	}

	p = do_netlog_exec(args);
	if (p == -1) {
		return -1;
	}
	g_newnet.log_pid = p;
	return 0;
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
		r = eslib_rtnetlink_linksetns(ifname, g_newnet.new_ns, 0);
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
	if (g_lognet) {
		if (setup_netlog()) {
			printf("could not setup netlog\n");
			goto netns_err;
		}
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

