/* (c) 2015 Michael R. Tirado -- GPLv3, GNU General Public License, version 3.
 * contact: mtirado418@gmail.com
 *
 * pod.h
 *
 */

#ifndef POD_H__
#define POD_H__

#ifndef FIREWALL_MAXFILTER
	#define FIREWALL_MAXFILTER (1024 * 32)
#endif

/* user config directory */
#ifndef JETTISON_USERCFG
	#define JETTISON_USERCFG "/etc/jettison/users"
#endif
struct newnet_param {
	char netfilter[FIREWALL_MAXFILTER]; /* firewall rules */
	int  filtersize;
	char addr[19];     /* ipv4 addr */
	char prefix[3];    /* netmask prefix */
	char dev[16];      /* master device name */
	char gateway[16];  /* to net  */
	unsigned int kind; /* RTNL_KIND_ in eslib_rtnetlink.h */
	unsigned char netmask; /* subnet mask, (prefix bits) */
};

/* put all podflag options near top, they are used as
 * bit flags, and we should keep their value as low as possible */
enum
{
	OPTION_NEWNET=0,
	OPTION_NEWPTS,
	OPTION_NOPROC,
	/*OPTION_SLOG,*/
	OPTION_HOME_EXEC,
#ifdef X11OPT
	OPTION_X11,
#endif
	/*
	 * anything above here is a pod flag that caller
	 * may need to know about, and handle externally.
	 */
	OPTION_PODFLAG_CUTOFF,

	OPTION_SECCOMP_ALLOW,
	OPTION_SECCOMP_BLOCK,
	OPTION_FILE,
	OPTION_HOME,

	OPTION_CAPABILITY,
	OPTION_MACHINEID,
	KWCOUNT
};


/* reads configuration for flags and chroot path
 * filepath - pod configuration file
 * outpath  - path to new chroot,
 * outflags - option flags
 *
 * outpath must be <= MAX_SYSTEMPATH for a safe memcpy
 */
int pod_prepare(char *filepath, char *outpath, unsigned int *outflags);

/*
 * if any failure occurs after pod_prepare or on pod_enter
 * we need to free the file data.
 */
int pod_free();

/*
 * enact options, and chroot to pods new path.
 */
int pod_enter();



#endif
