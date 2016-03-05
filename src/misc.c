/* (c) 2015 Michael R. Tirado -- GPLv3, GNU General Public License, version 3.
 * contact: mtirado418@gmail.com
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <termios.h>
#include <memory.h>
#include "misc.h"
#include "eslib/eslib.h"


/* setup some console termios defaults */
int console_setup(int fd_tty)
{
	struct termios tty;
	if (fd_tty == -1 || !isatty(fd_tty))
		return -1;

	if (tcgetattr(fd_tty, &tty))
		return -2;

	tty.c_cflag &= CBAUD|CBAUDEX|CSIZE|CSTOPB|PARENB|PARODD;
	tty.c_cflag |= HUPCL|CLOCAL|CREAD;

	tty.c_cc[VDISCARD]  = CDISCARD;
	tty.c_cc[VEOF]	    = CEOF;
	tty.c_cc[VEOL]	    = _POSIX_VDISABLE;
	tty.c_cc[VEOL2]	    = _POSIX_VDISABLE;
	tty.c_cc[VERASE]    = CERASE; /* ASCII DEL (0177) */
	tty.c_cc[VINTR]	    = CINTR;
	tty.c_cc[VKILL]	    = CKILL;
	tty.c_cc[VLNEXT]    = CLNEXT;
	tty.c_cc[VMIN]	    = 1;
	tty.c_cc[VQUIT]	    = CQUIT;
	tty.c_cc[VREPRINT]  = CREPRINT;
	tty.c_cc[VSTART]    = CSTART;
	tty.c_cc[VSTOP]	    = CSTOP;
	tty.c_cc[VSUSP]	    = CSUSP;
	tty.c_cc[VSWTC]	    = _POSIX_VDISABLE;
	tty.c_cc[VTIME]	    = 0;
	tty.c_cc[VWERASE]   = CWERASE;

	/*
	 *	Set pre and post processing
	 */
	tty.c_iflag = IGNPAR|ICRNL|IXON|IXANY;

	if (tcsetattr(fd_tty, TCSANOW, &tty))
		return -3;

	tcflush(fd_tty, TCIOFLUSH);
	return 0;

}

/*
 * create new pty device
 * return
 * fd_master	 - file descriptor for controlling side
 * outslave_path - path to slave device.
 * */
int pty_create(int *fd_master, int master_flags,
	       char outslave_path[MAX_SYSTEMPATH])
{
	int master;
	int slave;
	memset(outslave_path, 0, MAX_SYSTEMPATH);

	master = posix_openpt(O_RDWR | O_NOCTTY | master_flags);

	if (master == -1) {
		printf("openpt: %s\n", strerror(errno));
		return -1;
	}

	/* change slave owner to our real uid */
	if (grantpt(master)) {
		printf("grantpt: %s\n", strerror(errno));
		close(master);
		return -1;
	}
	if (unlockpt(master)) {
		printf("unlockpt: %s\n", strerror(errno));
		close(master);
		return -1;
	}
	if (ptsname_r(master, outslave_path, MAX_SYSTEMPATH-1)) {
		printf("ptsname_r: %s\n", strerror(errno));
		close(master);
		return -1;
	}

	slave = open(outslave_path, O_RDWR | O_NOCTTY);
	if (slave == -1) {
		printf("slave open(%s): %s\n", outslave_path, strerror(errno));
		close(master);
		return -1;
	}
	close(slave);

	*fd_master = master;
	return 0;
}


/* open tty device and make it our controlling terminal
 * maybe hang it up first.
 */
int switch_terminal(char *path, int hangup)
{
	int err;
	int fd_tty = open(path, O_CLOEXEC|O_RDWR|O_NONBLOCK);
	if (fd_tty == -1) {
		printf("open(%s): %s\n", path, strerror(errno));
		return -1;
	}
	if (!isatty(fd_tty)) {
		printf("not a tty\n");
		return -1;
	}
	if (ioctl(fd_tty, TIOCSCTTY, (void *)NULL)) {
		printf("ioctl error: %s\n", strerror(errno));
		return -1;
	}

	err = console_setup(fd_tty);
	if (err) {
		printf("(%d)console_setup: %s\n", err, strerror(errno));
		return -1;
	}

	if (hangup) {
		if (vhangup()) {
			printf("hangup: %s\n", strerror(errno));
			return -1;
		}
	}
	/* switch stdio fd's */
	if (dup2(fd_tty, STDIN_FILENO) != STDIN_FILENO
		|| dup2(fd_tty, STDOUT_FILENO) != STDOUT_FILENO
			|| dup2(fd_tty, STDERR_FILENO) != STDERR_FILENO) {
		printf("stdio dup error: %s\n", strerror(errno));
		return -1;
	}
	return 0;
}


int chop_trailing(char *string, unsigned int size, const char match)
{
	unsigned int i;
	if (!string)
		return -1;
	i = strnlen(string, size);
	if (i == 0 || i >= size)
		return -1;

	while (1)
	{
		--i;
		if(string[i] == match)
			string[i] = '\0';
		else
			return 0; /* no matches */
		if (i == 0)
			return 0;
	}
	return -1;
}


/*
 *  return pointer to static memory containing passwd line for the given uid,
 *  or NULL on error. memory is overwritten each call.
 */
#define FMAXLINE 4095*4
#define PASSWD_FILE "/etc/passwd"
static char g_storeline[FMAXLINE+1];
static char g_storefield[FMAXLINE+1];

char *passwd_fetchline(uid_t uid)
{
	char rdline[FMAXLINE+1];
	FILE *file;

	file = fopen(PASSWD_FILE, "r");
	if (file == NULL)
		return NULL;

	do
	{
		char uidstr[32];
		char *err = NULL;
		unsigned int count = 0;
		unsigned int i = 0;
		unsigned int z;
		unsigned int len;
		uid_t checkuid;

		if (fgets(rdline, FMAXLINE, file) == NULL) {
			printf("uid(%d) not found in %s?\n", uid, PASSWD_FILE);
			goto err_return;
		}
		if (strnlen(rdline, FMAXLINE) >= FMAXLINE) {
			printf("line too long, increase FMAXLINE\n");
			goto err_return;
		}

		/* skip to uid column */
		while(i < FMAXLINE) {
			if (rdline[i] == ':') {
				++count;
			}
			if (count == 2)
				break;
			++i;
		}
		if (count != 2)
			goto err_return;

		z = i+1;
		/*find uid stringlen*/
		while(++i < FMAXLINE)
		{
			if (rdline[i] == ':')
				break;
		}
		if (i >= FMAXLINE)
			goto err_return;

		len = i - z;
		if (len == 0 || len >= sizeof(uidstr)) {
			printf("uid string error\n");
			goto err_return;
		}

		strncpy(uidstr, &rdline[z], len);
		uidstr[len] = '\0';
		errno = 0;
		checkuid = strtol(uidstr, &err, 10);
		if (errno || *err) {
			printf("error converting string to long int\n");
			goto err_return;
		}
		if (uid == checkuid) {
			strncpy(g_storeline, rdline, FMAXLINE);
			g_storeline[FMAXLINE] = '\0';
			fclose(file);
			return g_storeline;
		}
	}
	while(1);


err_return:
	fclose(file);
	return NULL;
}


char *passwd_getfield(char *line, unsigned int field)
{
	unsigned int i;
	int prev = -1;
	unsigned int count = 0;

	if (!line || field >= PASSWD_FIELDS)
		return NULL;

	memset(g_storefield, 0, sizeof(g_storefield));
	for (i = 0; i < FMAXLINE; ++i)
	{
		if (line[i] == ':' || line[i] == '\0') {
			if (count == field) {
				strncpy(g_storefield, &line[prev+1], i-(prev+1));
				return g_storefield;
			}
			if (++count >= PASSWD_FIELDS) {
				return NULL;
			}
			prev = i;
		}
	}
	return NULL;
}

/*
 * shuffle data starting at index, swap with value located at idx+amount
 * if amount is too high, wrap around to idx0+remainder
 * uses bitmask to only swap masked bits: 0xff would swap the entire byte
 */
static int shuffle_bits(unsigned char *data, size_t size, size_t idx,
			size_t amount, unsigned char bitmask)
{
	size_t dest;
	unsigned char tmp;

	if (!data)
		return -1;
	if (size < 2)
		return -1;

	/* wrap around if too big */
	idx %= size;
	dest = (idx + amount) % size;
	tmp = data[dest];
	data[dest] = (data[dest] & ~bitmask) | (data[idx] & bitmask);
	data[idx]  = (data[idx]  & ~bitmask) | (tmp & bitmask);
	return 0;
}

/*
 *  missing machine-id causes failure on systems that have disabled dbus.
 *  we need a way to create this file if absent, and program links dbus lib.
 */
int create_machineid(char *path, char *newid, unsigned int entropy)
{
	char idstr[33];
	unsigned int i,c;
	int fd;
	errno = 0;

	if (!path)
		return -1;

	if (!newid) {
		unsigned char randx[16];
		char hecks[16] = {'0','1','2','3','4','5','6','7',
				  '8','9','a','b','c','d','e','f'};

		unsigned char h1 = entropy+hecks[entropy%15];
		for (i = 0; i < 16; i += 4)
		{
			memcpy(&randx[i], &entropy, sizeof(entropy));
			/*randx[i]   = 0xf0;
			randx[i+1] = 0x60;
			randx[i+2] = 0x0f;
			randx[i+3] = 0xf6;
			this still isn't a great rng, but it's good enough
			if not using below code, first char repeats
		        */
			randx[i+1] += randx[i] + h1;
			randx[i+2] += randx[i+1] + randx[i];
			randx[i+3] += randx[i+2] + randx[i+1];
			h1 = randx[i+3];
		}
		/* scramble bits */
		for (i = 0; i < 1024 ; ++i)
		{
			unsigned char e = entropy+i;
			unsigned char e2= randx[i%15]+e;
			if (shuffle_bits(randx, 16, 0, e, e2)) {
					return -1;
			}
			/*printf("iter1: %d\n", randx[0]);*/
		}
		/* generate hex string */
		for (i = 0, c = 0; i < 16; ++i)
		{
			unsigned long idx1,idx2;
			idx1 = (randx[i] & 0x0f);
			idx2 = (randx[i] & 0xf0) >> 4;
			idstr[c++] = hecks[idx1];
			idstr[c++] = hecks[idx2];
		}
		idstr[32] = '\0';
		newid = idstr;
	}

	/* validate hex string */
	for (i = 0; i < 32; ++i)
	{
		if (newid[i] >= '0' && newid[i] <= '9') {
			continue;
		}
		else if (newid[i] >= 'a' && newid[i] <= 'f') {
			continue;
		}
		else {
			printf("invalid hex char");
			return -1;
		}
	}
	printf("newid: %s\n", idstr);

	/* create new file */
	fd = open(path, O_TRUNC|O_CREAT|O_RDWR, 0750);
	if (fd == -1) {
		printf("open: %s\n", strerror(errno));
		return -1;
	}
	if (write(fd, newid, 32) != 32) {
		printf("machine-id write error: %s\n", strerror(errno));
		close(fd);
		return -1;
	}
	close(fd);
	return 0;
}








