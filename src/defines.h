#ifndef DEFINES_H__
#define DEFINES_H__

/*
 *  you can add the following to DEFINES in makefile so they are passed
 *  directly as a compiler flag.
 *
 *  global defines not documented here:
 *  -DUSE_FILE_CAPS     -- enables file capabilities
 *  -DX11OPT            -- x11 support
 *  -DNEWNET_IPVLAN     -- can create ipvlans
 *  -DNEWNET_MACVLAN    -- can create macvlans
 *  -DPODROOT_HOME_OVERRIDE -- developer hack to let user control podroot directories.
 *  				use with pkg-autopod.sh for automated build containers.
 *
 *  TODO there are possibly more
 */


#ifndef MIN_STACKSIZE
	#define MIN_STACKSIZE (64 * 1024) /* 64 KB */
#endif
#ifndef MAX_STACKSIZE
	#define MAX_STACKSIZE  (1024 * 1024 * 16) /* 16MB */
#endif
/* pod init program */
#ifndef INIT_PATH
	#define INIT_PATH="/usr/local/bin/jettison_init"
#endif
#ifndef PASSWD_FILE
	#define PASSWD_FILE "/etc/passwd"
#endif
#ifndef GROUP_FILE
	#define GROUP_FILE "/etc/group"
#endif

/* hack to write daemon glibc output in linebuffered mode */
#ifndef PRELOAD_PATH
	#define PRELOAD_PATH="/usr/local/bin/jettison_preload.so"
#endif
/* if user doesn't supply prefix, assume this one */
#ifndef DEFAULT_NETMASK_PREFIX
	#define DEFAULT_NETMASK_PREFIX 24
#endif
#ifndef FIREWALL_MAXFILTER
	#define FIREWALL_MAXFILTER (1024 * 16)
#endif
/* user config directory */
#ifndef JETTISON_USERCFG
	#define JETTISON_USERCFG "/etc/jettison/users"
#endif
/* system-wide --blacklist */
#ifndef JETTISON_BLACKLIST
	#define JETTISON_BLACKLIST "/etc/jettison/blacklist"
#endif
#ifndef JETTISON_STOCKPODS
	#define JETTISON_STOCKPODS "/etc/jettison/pods"
#endif
/* hard limit number of ip/macvlan a user can create */
#ifndef JETTISON_IPVLAN_LIMIT
	#define JETTISON_IPVLAN_LIMIT 30
#endif

/* prevent race condition when counting ip/macvlans*/
#ifndef IPVLAN_COUNT_LOCKFILE
	#define IPVLAN_COUNT_LOCKFILE "/var/lock/jettison/ipvlan_counter"
#endif

/* 3'rd party programs for network setup/logging*/
#ifndef FIREWALL_SAVE
	#define FIREWALL_SAVE "iptables-save"
#endif
#ifndef FIREWALL_RESTORE
	#define FIREWALL_RESTORE "iptables-restore"
#endif
#ifndef FIREWALL6_SAVE
	#define FIREWALL6_SAVE "ip6tables-save"
#endif
#ifndef FIREWALL6_RESTORE
	#define FIREWALL6_RESTORE "ip6tables-restore"
#endif

#ifndef FIREWALL_PROG
	#define FIREWALL_PROG "/usr/sbin/xtables-multi"
#endif
#ifndef NETLOG_PROG
	#define NETLOG_PROG "/usr/sbin/tcpdump"
#endif
#ifndef NETLOG_GROUP
	#define NETLOG_GROUP "nobody"
#endif


#endif
