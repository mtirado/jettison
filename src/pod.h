/* (c) 2015 Michael R. Tirado -- GPLv3, GNU General Public License, version 3.
 * contact: mtirado418@gmail.com
 *
 * pod.h
 *
 */

#ifndef POD_H__
#define POD_H__

struct newnet_param;
struct user_privs;
struct seccomp_program;
/* podflags are above cutoff, they are used as 32bit flags */
enum
{
	OPTION_NEWNET=0,
	OPTION_NEWPTS,
	OPTION_NOPROC,
	/*OPTION_SLOG,*/
	OPTION_HOME_EXEC,
	OPTION_TMP_EXEC,
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
 * filepath  - pod configuration file
 * outpath   - path to new chroot,
 * newnet    - network namespace options
 * blacklist - if non-zero, use systemwide blacklist
 * outflags  - option flags
 *
 * outpath must be <= MAX_SYSTEMPATH for a safe memcpy
 */
int pod_prepare(char *filepath,
		char *outpath,
		struct newnet_param *newnet,
		struct seccomp_program *seccfilter,
		unsigned int blacklist,
		struct user_privs *privs,
		unsigned int *outflags);

int pod_config_netns();
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
