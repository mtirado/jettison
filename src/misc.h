/* (c) 2015 Michael R. Tirado -- GPLv3, GNU General Public License, version 3.
 * contact: mtirado418@gmail.com
 */
#ifndef MISC_H__
#define MISC_H__

#include "defines.h"

#include <linux/audit.h>
#include <linux/seccomp.h>
#include "eslib/eslib_fortify.h"
#include "init_cmdr.h"

/* maximum line length for user privilege file */
#define MAX_PRIVLN 128
struct newnet_param {
	int  active;
	char addr[19];         /* ipv4 addr */
	char hwaddr[18];       /* mac addr */
	char gateway[16];      /* to net  */
	char dev[16];          /* master device name */
	char prefix[3];        /* netmask prefix */
	unsigned char netmask; /* subnet mask, prefix bits */
	unsigned int  kind;    /* RTNL_KIND_ in eslib_rtnetlink.h */
	pid_t log_pid;         /* logger process */
	int log_filesize;      /* maximum individual file size */
	int log_count;         /* number of rotation files */
	int root_ns;           /* initial net namespace */
	int new_ns;            /* new net namespace */
};
struct user_privs {
	unsigned int newpts;        /* can create newpts instances */
	unsigned int ipvlan_limit;  /* maximum number of ipvlan's */
};


/* node flags */
#define NODE_HOME     1 /* node created using home option */
#define NODE_EMPTY    2 /* mounted on itself(dest/dest) instead of (src/dest)*/
#define NODE_HOMEROOT 4 /* home root is a special case that must be sorted */
#define NODE_PODROOT_HOME_OVERRIDE 8 /* dev hack that gives user control over pod root */
struct path_node
{
	struct path_node *next;
	char src[MAX_SYSTEMPATH];
	char dest[MAX_SYSTEMPATH];
	unsigned long mntflags;
	unsigned long nodetype;
	/* strlens, no null terminator */
	unsigned int srclen;
	unsigned int destlen;
};

int pathnode_bind(struct path_node *node);


/* chop matching character from the end of string
 * returns 0 on first non matching character, -1 on error.
 * size is the string array size (including null terminator)
 */
int chop_trailing(char *string, unsigned int size, const char match);

/* return -1 on error, c is output */
int getch(char *c);
/* close everything if exemptions array is NULL */
int close_descriptors(int *exemptions, int exemptcount);

/* tty/console */
int console_setup();
/* slave path should be an array[MAX_SYSTEMPATH] */
int pty_create(int *fd_master, int master_flags,
	       char outslave_path[MAX_SYSTEMPATH]);
int switch_terminal(char *path, int hangup);


/* --------------  passwd/group file interface --------------- */
enum {
	/* passwd fields */
	PASSWD_USER = 0,
	PASSWD_PASS,
	PASSWD_UID,
	PASSWD_GID,
	PASSWD_FULLNAME,
	PASSWD_HOME,
	PASSWD_SHELL,
	PASSWD_FIELDS
};
enum {
	/* group fields */
	GROUP_NAME = 0,
	GROUP_PASS,
	GROUP_GID,
	GROUP_USERS
};

/* return the first passwd entry that matches uid, points to static array */
char *passwd_fetchline_byid(int id, char *filename);
char *passwd_fetchline_byname(char *username, char *filename);
/* get specific passwd field, destroys line by inserting null terminator */
char *passwd_getfield(char *line, unsigned int field);

/* returns -1 on error */
uid_t get_user_id(char *username);
gid_t get_group_id(char *username);


/* ------------------------------------------------------------ */

int shuffle_bits(unsigned char *data, size_t size, size_t idx,
		size_t amount, unsigned char bitmask);
int randhex(char *out, unsigned int size,
		unsigned int entropy, unsigned int cycles);

/* create a new machine-id file
 * path is machine-id file path
 * newid is 32 hexadecimal characters.
 * if newid is null, a random string is generated.
 */
int create_machineid(char *path, char *newid, unsigned int entropy);

int downgrade_caps();
int capbset_drop(int fcaps[NUM_OF_CAPS]);
#endif










