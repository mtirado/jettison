/* (c) 2015 Michael R. Tirado -- GPLv3, GNU General Public License, version 3.
 * contact: mtirado418@gmail.com
 *
 * pod.h
 *
 */

#ifndef POD_H__
#define POD_H__


/* put all podflag options near top, they are used as
 * bit flags, and we should keep their value as low as possible */
enum
{
	OPTION_ROOTPID=0,
	OPTION_NEWNET,
	OPTION_NEWPTS,
	OPTION_NOPROC,
	OPTION_SLOG,
	OPTION_HOME_EXEC,

	/*
	 * anything above here is a pod flag that caller
	 * may need to know about, and handle externally.
	 */
	OPTION_PODFLAG_CUTOFF,

	OPTION_SECCOMP_ALLOW,
	OPTION_SECCOMP_BLOCK,
	OPTION_FILE,
	OPTION_HOME,

	/*OPTION_CAP_PSET*/
	OPTION_CAP_BSET,
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
