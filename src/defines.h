#ifndef DEFINES_H__
#define DEFINES_H__

/* override these with -D compiler flag */
/* highest stack value system allows */
#ifndef MAX_SYSTEMSTACK
	#define MAX_SYSTEMSTACK  (1024 * 1024 * 16) /* 16MB */
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

/* hack to make daemon stdio write in linebuffered mode */
#ifndef PRELOAD_PATH
	#define PRELOAD_PATH="/usr/local/bin/jettison_preload.so"
#endif
#ifndef DEFAULT_NETMASK_PREFIX
	#define DEFAULT_NETMASK_PREFIX 24
#endif
#ifndef FIREWALL_MAXFILTER
	#define FIREWALL_MAXFILTER (1024 * 32)
#endif
/* user config directory */
#ifndef JETTISON_USERCFG
	#define JETTISON_USERCFG "/etc/jettison/users"
#endif
/* hard limit number of ip/macvlan a user can create */
#ifndef JETTISON_IPVLAN_LIMIT
	#define JETTISON_IPVLAN_LIMIT 30
#endif
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
#ifndef NETLOG_PROG
	#define NETLOG_PROG "/usr/sbin/tcpdump"
#endif
#ifndef NETLOG_GROUP
	#define NETLOG_GROUP "nobody"
#endif
#ifndef IPVLAN_COUNT_LOCKFILE
	#define IPVLAN_COUNT_LOCKFILE "/var/lock/jettison/ipvlan_counter"
#endif


#endif
