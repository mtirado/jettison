/* (c) 2015 Michael R. Tirado -- GPLv3, GNU General Public License, version 3.
 * contact: mtirado418@gmail.com
 */
#ifndef MISC_H__
#define MISC_H__


/* chop matching character from the end of string
 * returns 0 on first non matching character, -1 on error.
 * size is the string array size (including null terminator)
 */
int chop_trailing(char *string, unsigned int size, const char match);

/* return -1 on error, c is output */
int getch(char *c);

/* tty/console */
int console_setup();
/* slave path should be an array[MAX_SYSTEMPATH] */
int pty_create(int *fd_master, int master_flags,
	       char outslave_path[MAX_SYSTEMPATH]);
int switch_terminal(char *path, int hangup);


/* --------------  passwd help --------------- */
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

/* return the first passwd entry that matches uid, points to static array */
char *passwd_fetchline(uid_t uid);
/* get specific passwd field, destroys line by inserting null terminator */
char *passwd_getfield(char *line, unsigned int field);

/* create a new machine-id file
 * path is machine-id file path
 * newid is 32 hexadecimal characters.
 * if newid is null, a random string is generated.
 */
int create_machineid(char *path, char *newid, unsigned int entropy);
int shuffle_bits(unsigned char *data, size_t size, size_t idx,
			size_t amount, unsigned char bitmask);

#endif










