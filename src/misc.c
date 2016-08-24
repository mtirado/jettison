/* (c) 2015 Michael R. Tirado -- GPLv3, GNU General Public License, version 3.
 * contact: mtirado418@gmail.com
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <termios.h>
#include <memory.h>
#include "misc.h"
#include "eslib/eslib.h"

#define FMAXLINE 4095*4
static char g_storeline[FMAXLINE+1];
static char g_storefield[FMAXLINE+1];

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

	if (fd_master == NULL || outslave_path == NULL)
		return -1;

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
	int fd_tty;

	if (path == NULL)
		return -1;

	fd_tty = open(path, O_CLOEXEC|O_RDWR|O_NONBLOCK);
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
char *passwd_fetchline_byname(char *username, const char *filename)
{
	char rdline[FMAXLINE+1];
	FILE *file;

	if (username == NULL || filename == NULL)
		return NULL;
	if (strnlen(username, FMAXLINE) >= FMAXLINE)
		return NULL;
	if (strnlen(filename, MAX_SYSTEMPATH) >= MAX_SYSTEMPATH)
		return NULL;

	file = fopen(filename, "r");
	if (file == NULL)
		return NULL;

	do
	{
		unsigned int len = 0;

		if (fgets(rdline, FMAXLINE, file) == NULL) {
			printf("user %s not found in %s?\n", username, filename);
			goto err_return;
		}
		if (strnlen(rdline, FMAXLINE) >= FMAXLINE) {
			printf("line too long.\n");
			goto err_return;
		}

		/* find name stringlen */
		while(len < FMAXLINE)
		{
			if (rdline[len] == ':')
				break;
			++len;
		}
		if (len >= FMAXLINE || len == 0) {
			printf("username string error\n");
			goto err_return;
		}

		if (strncmp(username, rdline, len) == 0) {
			if (rdline[len] == ':') {
				strncpy(g_storeline, rdline, FMAXLINE);
				g_storeline[FMAXLINE] = '\0';
				fclose(file);
				return g_storeline;
			}
		}
	}
	while(1);


err_return:
	fclose(file);
	return NULL;
}

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
			printf("line too long.\n");
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
		if (errno || err == NULL || *err) {
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
int shuffle_bits(unsigned char *data, size_t size, size_t idx,
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

/* assumes overflows are not saturated, does not null terminate output */
int randhex(char *out, unsigned int size, unsigned int entropy, unsigned int cycles)
{
	const char hecks[16] = {'0','1','2','3','4','5','6','7',
			  '8','9','a','b','c','d','e','f'};
	unsigned int i, z;
	unsigned int iterations;
	unsigned char h1;
	if (size != 0 && size % 4 != 0) {
		printf("size must be divisible by 4 \n");
		return -1;
	}
	if (size > 1024*1024) {
		printf("size limited to 1MB\n");
		return -1;
	}
	if (cycles > 3000) {
		printf("cycles limited to 3000\n");
		return -1;
	}
	iterations = size * cycles;
	if (iterations == 0 || out == NULL)
		return -1;

	entropy += 99;
	h1 = entropy+hecks[entropy%16];
	for (i = 0; i < size; i += 4)
	{
		memcpy(&out[i], &entropy, sizeof(entropy));
		out[i+1] += out[i] + h1;
		out[i+2] += out[i+1] + out[i];
		out[i+3] += out[i+2] + out[i+1];
		h1 += out[i+3]+entropy;
	}
	for (z = 0; z < 15; ++z)
	{
		for (i = 0; i < size; i += 4)
		{
			out[i+1] += out[i] + h1;
			out[i+2] += out[i+1] + out[i];
			out[i+3] += out[i+2] + out[i+1];
			h1 += out[i+3]+entropy;
			++entropy;
		}
	}
	/* scramble bits */
	for (i = 0; i < iterations ; ++i)
	{
		unsigned int  e  = entropy+i;
		unsigned char e2 = out[e%size]+i;
		out[i%size] += e+e2;
		if (shuffle_bits((unsigned char *)out, size, entropy, e, e2)) {
			return -1;
		}
	}
	/* generate hex string */
	for (i = 0; i < size; ++i)
	{
		unsigned char c = out[i];
		out[i] = hecks[c%16];
	}
	return 0;
}

/* some libraries fail to load if this file is missing */
int create_machineid(char *path, char *newid, unsigned int entropy)
{
	char idstr[33];
	unsigned int i;
	int fd;
	errno = 0;

	if (!path)
		return -1;

	if (!newid) {
		if (randhex(idstr, 32, entropy, 1200)) {
			printf("couldn't get random hex string\n");
			return -1;
		}
		newid = idstr;
	}
	else {
		if (strnlen(newid, 33) != 32) {
			printf("machine-id is not 32 characters\n");
			return -1;
		}
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
			printf("invalid hex char\n");
			return -1;
		}
	}
	newid[32] = '\0';
	/* create new file */
	fd = open(path, O_TRUNC|O_CREAT|O_RDWR, 0775);
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
	if (chmod(path, 0775)) {
		printf("chmod: %s\n", strerror(errno));
		return -1;
	}
	return 0;
}

int getch(char *c)
{
	struct termios orig, tmp;
	if (c == NULL)
		return -1;

	if (tcgetattr(STDIN_FILENO, &orig))
		return -1;
	memcpy(&tmp, &orig, sizeof(tmp));
	tmp.c_lflag &= ~(ICANON|ECHO);

	if (tcsetattr(STDIN_FILENO, TCSANOW, &tmp))
		return -1;

	if (read(STDIN_FILENO, c, 1) != 1) {
		printf("getch: %s\n", strerror(errno));
		return -1;
	}

	if (tcsetattr(STDIN_FILENO, TCSANOW, &orig))
		return -1;

	return 0;
}

int pathnode_bind(struct path_node *node)
{
	if (node == NULL)
		return -1;
	if (node->nodetype == NODE_EMPTY) {
		printf("do_empty(%s, %s)\n", node->src, node->dest);
		if (mount(node->dest, node->dest, NULL, MS_BIND, NULL)) {
			printf("home or empty mount failed: %s\n", strerror(errno));
			return -1;
		}
	}
	else {
		printf("pathnode_bind(%s, %s)\n", node->src, node->dest);
		if (mount(node->src, node->dest, NULL, MS_BIND, NULL)) {
			printf("mount failed: %s\n", strerror(errno));
			return -1;
		}
	}
	/* remount */
	if (mount(NULL, node->dest, NULL, MS_BIND|MS_REMOUNT|node->mntflags, NULL)) {
		printf("remount failed: %s\n", strerror(errno));
		return -1;
	}
	if (mount(NULL, node->dest, NULL, MS_SLAVE|MS_REC, NULL)) {
		printf("could not make slave: %s\n", strerror(errno));
		return -1;
	}
	return 0;
}

uid_t get_user_id(char *username)
{
	char *pwline;
	char *pwuid;
	char *err = NULL;
	unsigned long uid;

	if (username == NULL)
		return -1;

	pwline = passwd_fetchline_byname(username, PASSWD_FILE);
	if (pwline == NULL) {
		printf("could not find user: %s\n", username);
		return -1;
	}
	pwuid = passwd_getfield(pwline, PASSWD_UID);
	if (pwuid == NULL) {
		printf("could not find uid in passwd file\n");
		return -1;
	}
	errno = 0;
	uid = strtoul(pwuid, &err, 10);
	if (errno || err == NULL || *err) {
		printf("error converting string to ulong\n");
		return -1;
	}
	if (uid == 0 || (long)uid == -1) {
		printf("absurd uid value\n");
		return -1;
	}
	return uid;
}

gid_t get_group_id(char *groupname)
{
	char *grline;
	char *grgid;
	char *err = NULL;
	unsigned long gid;

	if (groupname == NULL)
		return -1;

	grline = passwd_fetchline_byname(groupname, GROUP_FILE);
	if (grline == NULL) {
		printf("could not find user: %s\n", groupname);
		return -1;
	}
	grgid = passwd_getfield(grline, GROUP_GID);
	if (grgid == NULL) {
		printf("could not find gid in group file\n");
		return -1;
	}
	errno = 0;
	gid = strtoul(grgid, &err, 10);
	if (errno || err == NULL || *err) {
		printf("error converting string to ulong\n");
		return -1;
	}
	if (gid == 0 || (long)gid == -1) {
		printf("absurd gid value\n");
		return -1;
	}
	return gid;
}
#define FAILSAFE_FLIMIT 4096
int close_descriptors(int *exemptions, int exemptcount)
{
	int fdcount;
	int *fdlist;
	int i;

	if (exemptcount <= 0 || exemptions == NULL) {
		exemptions = NULL;
		exemptcount = 0;
	}

	fdcount = eslib_proc_getfds(getpid(), &fdlist);
	if (fdcount == -1) { /* there was problem reading /proc/PID */
		struct rlimit rlim;
		int fdcount = FAILSAFE_FLIMIT;

		memset(&rlim, 0, sizeof(rlim));
		if (getrlimit(RLIMIT_NOFILE, &rlim) == 0) {
			if (rlim.rlim_cur < 128) {
				rlim.rlim_cur = 128;
			}
			fdcount = rlim.rlim_cur;
		}
		for (i = 0; i < fdcount; ++i)
		{
			if (exemptions) {
				int z;
				for (z = 0; z < exemptcount; ++z)
				{
					if (exemptions[z] == i) {
						z = -1;
						break;
					}
				}
				if (z == -1) {
					continue;
				}
				close(i);
			}
			else {
				close(i);
			}
		}
		return 0;
	}

	for (i = 0; i < fdcount; ++i)
	{
		if (exemptions) {
			int z;
			for (z = 0; z < exemptcount; ++z)
			{
				if(fdlist[i] == exemptions[z]) {
					z = -1;
					break;
				}
			}
			if (z == -1) {
				continue;
			}
		}
		close(fdlist[i]);
	}
	free(fdlist);
	return 0;
}
