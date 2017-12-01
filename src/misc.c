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
#include <linux/capability.h>
#include <linux/securebits.h>
#include <sys/prctl.h>
#include "eslib/eslib.h"
#include "misc.h"

#define PASSWD_MAX (1024*1024*100)
#define FMAXLINE 1023

static char g_storeline[FMAXLINE+1];
static char g_storefield[FMAXLINE+1];

extern int capset(cap_user_header_t header, cap_user_data_t data);
extern int capget(cap_user_header_t header, const cap_user_data_t data);

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

/* read text file and makes sure it's null terminated, outlen does not include '\0'
 * caller is responsible for freeing allocated buffer
 */
char *load_text_file(char *filepath, const size_t maxsize, size_t *outlen)
{
	char *fbuf = NULL;
	size_t flen = 0;
	if (filepath == NULL || outlen == NULL || maxsize <= 1)
		return NULL;

	fbuf = calloc(1, 4096);
	if (fbuf == NULL)
		return NULL;

	if (eslib_file_read_full(filepath, fbuf, 4096 - 1, &flen)) {
		if (errno == EOVERFLOW) {
			char *re_fbuf = NULL;
			if (flen + 1 >= maxsize)
				goto failed;
			re_fbuf = realloc(fbuf, flen + 1);
			if (re_fbuf == NULL)
				goto failed;
			fbuf = re_fbuf;
			if (eslib_file_read_full(filepath, fbuf, flen + 1, &flen))
				goto failed;
		}
		else {
			goto failed;
		}
	}
	fbuf[flen] = '\0';
	*outlen = flen;
	if (flen == 0) {
		errno = ECANCELED;
		goto failed;
	}
	return fbuf;

failed:
	free(fbuf);
	return NULL;
}

char *passwd_getfield(char *line, unsigned int field)
{
	unsigned int i;
	unsigned int count = 0;
	unsigned int start = 0;

	if (!line || field >= PASSWD_FIELDS)
		return NULL;

	memset(g_storefield, 0, sizeof(g_storefield));
	for (i = 0; i < FMAXLINE; ++i)
	{
		if (line[i] == ':' || line[i] == '\0') {
			if (count == field) {
				unsigned int len = i - start;
				if (es_strcopy(g_storefield, &line[start], len+1, NULL)) {
					if (errno != EOVERFLOW)
						return NULL;
				}
				return g_storefield;
			}
			if (++count >= PASSWD_FIELDS) {
				break;
			}
			start = i+1;
		}
	}
	return NULL;
}

/*
 *  return pointer to static memory containing passwd line for the given uid,
 *  or NULL on error. memory is overwritten each call.
 *
 */
char *passwd_fetchline_byname(char *username, char *filename)
{
	char *fbuf;
	size_t flen;
	size_t usrname_len;
	char *line;
	unsigned int pos = 0;

	if (username == NULL || filename == NULL)
		return NULL;
	if (strnlen(filename, MAX_SYSTEMPATH) >= MAX_SYSTEMPATH)
		return NULL;

	fbuf = load_text_file(filename, PASSWD_MAX, &flen);
	if (fbuf == NULL) {
		printf("couldn't load passwd file: %s\n", filename);
		return NULL;
	}
	usrname_len = strnlen(username, FMAXLINE);
	if (usrname_len >= FMAXLINE/2 || usrname_len == 0)
		goto err_free;
	if (!eslib_string_is_sane(fbuf, flen))
		goto err_free;
	if (eslib_string_tokenize(fbuf, flen, "\n"))
		goto err_free;
	memset(g_storeline, 0, FMAXLINE);
	line = fbuf;
	do {
		char *field;
		unsigned int adv;

		line = eslib_string_toke(fbuf, pos, flen, &adv);
		pos += adv;
		if (line == NULL)
			break;
		field = passwd_getfield(line, PASSWD_USER);
		if (field == NULL)
			goto err_free;
		if (strncmp(username, field, usrname_len) == 0) {
			if (field[usrname_len] == '\0') {
				if (es_strcopy(g_storeline, line, FMAXLINE, NULL))
					goto err_free;
				free(fbuf);
				g_storeline[FMAXLINE] = '\0';
				return g_storeline;
			}
		}
	} while (line);

	errno = ENOENT;
	free(fbuf);
	return NULL;

err_free:
	printf("problem reading passwd file: %s\n", filename);
	free(fbuf);
	return NULL;
}


char *passwd_fetchline_byid(uint32_t uid, char *filename)
{
	char *fbuf;
	size_t flen;
	char *line;
	unsigned int pos = 0;
	uint32_t check_uid;

	if (filename == NULL || strnlen(filename, MAX_SYSTEMPATH) >= MAX_SYSTEMPATH)
		return NULL;

	fbuf = load_text_file(filename, PASSWD_MAX, &flen);
	if (fbuf == NULL) {
		printf("couldn't load passwd file: %s\n", filename);
		return NULL;
	}
	if (!eslib_string_is_sane(fbuf, flen))
		goto err_free;
	if (eslib_string_tokenize(fbuf, flen, "\n"))
		goto err_free;

	memset(g_storeline, 0, sizeof(g_storeline));
	do {
		char *field;
		unsigned int adv;

		line = eslib_string_toke(fbuf, pos, flen, &adv);
		pos += adv;
		if (line == NULL)
			break;
		field = passwd_getfield(line, PASSWD_UID);
		if (field == NULL)
			goto err_free;

		if (eslib_string_to_u32(field, &check_uid))
			goto err_free;
		if (uid == check_uid) {
			es_strcopy(g_storeline, line, FMAXLINE, NULL);
			g_storeline[FMAXLINE] = '\0';
			return g_storeline;
		}
	} while (line);

	errno = ENOENT;
	free(fbuf);
	return NULL;
err_free:
	printf("problem reading passwd file: %s\n", filename);
	free(fbuf);
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
	if ((long)uid == -1) {
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

	fdcount = eslib_proc_alloc_fdlist(getpid(), &fdlist);
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

int downgrade_caps()
{
	struct __user_cap_header_struct hdr;
	struct __user_cap_data_struct   data[2];
	int i;

	memset(&hdr, 0, sizeof(hdr));
	memset(data, 0, sizeof(data));
	hdr.version = _LINUX_CAPABILITY_VERSION_3;

	for(i = 0; i < NUM_OF_CAPS; ++i)
	{
		/* we need to temporarily hold on to these caps
		 * TODO drop setuid if not using --lognet, and net_admin
		 * and net_raw if not using ipvlan / --lognet */
		if (i == CAP_SYS_CHROOT
				|| i == CAP_SYS_ADMIN
				|| i == CAP_NET_ADMIN
				|| i == CAP_NET_RAW
				|| i == CAP_CHOWN
				|| i == CAP_SETGID
				|| i == CAP_SETUID
				|| i == CAP_SETPCAP) {
			data[CAP_TO_INDEX(i)].permitted |= CAP_TO_MASK(i);
			/* these dont need to be in effective set */
			if (i != CAP_NET_RAW && i != CAP_SETUID) {
				data[CAP_TO_INDEX(i)].effective |= CAP_TO_MASK(i);
			}
		}
	}
	/* don't grant caps on uid change */
	if (prctl(PR_SET_SECUREBITS,
			SECBIT_KEEP_CAPS_LOCKED		|
			SECBIT_NO_SETUID_FIXUP		|
			SECBIT_NO_SETUID_FIXUP_LOCKED)) {
		printf("prctl(): %s\n", strerror(errno));
		return -1;
	}

	if (capset(&hdr, data)) {
		printf("capset: %s\r\n", strerror(errno));
		printf("cap version: %p\r\n", (void *)hdr.version);
		printf("pid: %d\r\n", hdr.pid);
		return -1;
	}
	return 0;
}

static int cap_blisted(unsigned long cap)
{
	if (cap >= NUM_OF_CAPS) {
		printf("cap out of bounds\n");
		return 1;
	}

	switch(cap)
	{
		case CAP_MKNOD:
			printf("CAP_MKNOD is prohibited\n");
			return 1;
		case CAP_SYS_MODULE:
			printf("CAP_SYS_MODULE is prohibited\n");
			return 1;
		case CAP_SETPCAP:
			printf("CAP_SETPCAP is prohibited\n");
			return 1;
		case CAP_SETFCAP:
			printf("CAP_SETFCAP is prohibited\n");
			return 1;
		case CAP_DAC_OVERRIDE:
			printf("CAP_DAC_OVERRIDE is prohibited\n");
			return 1;
		case CAP_SYS_ADMIN: /* don't ever allow remounts... */
			printf("CAP_SYS_ADMIN is prohibited\n");
			return 1;
		case CAP_LINUX_IMMUTABLE:
			printf("CAP_LINUX_IMMUTABLE is prohibited\n");
			return 1;
		case CAP_MAC_OVERRIDE:
			printf("CAP_MAC_OVERRIDE is prohibited\n");
			return 1;
		case CAP_MAC_ADMIN:
			printf("CAP_MAC_ADMIN is prohibited\n");
			return 1;
		case CAP_CHOWN:
			printf("CAP_CHOWN is prohibited\n");
			return 1;
		case CAP_BLOCK_SUSPEND:
			printf("CAP_BLOCK_SUSPEND is prohibited\n");
			return 1;
		case CAP_SETUID:
			printf("CAP_SETUID is prohibited\n");
			return 1;
		case CAP_SETGID:
			printf("CAP_SETGID is prohibited\n");
			return 1;
		case CAP_FSETID:
			printf("CAP_SETFUID is prohibited\n");
			return 1;
		case CAP_KILL:
			printf("CAP_KILL is prohibited\n");
			return 1;
		case CAP_SYS_TIME:
			printf("CAP_SYS_TIME is prohibited\n");
			return 1;
		/*case CAP_SYSLOG:
			printf("CAP_SYSLOG is prohibited\n");
			return 1;*/
		case CAP_SYS_CHROOT:
			printf("CAP_SYS_CHROOT is prohibited\n");
			return 1;
		case CAP_IPC_OWNER:
			printf("CAP_IPC_OWNER is prohibited\n");
			return 1;
		case CAP_SYS_PTRACE:
			printf("CAP_SYS_PTRACE is prohibited\n");
			return 1;
		/*case CAP_DAC_READ_SEARCH:
			printf("CAP_DAC_READ_SEARCH is prohibited\n");
			return 1;*/
	default:
		return 0;
	}
}

int capbset_drop(int fcaps[NUM_OF_CAPS])
{
	unsigned long i;
	unsigned int c = 0;

	for(i = 0; i < NUM_OF_CAPS; ++i)
	{
		/* allow requested file caps if not blacklisted */
		if (fcaps[i] && !cap_blisted(i)) {
			if (i > CAP_LAST_CAP) {
			       return -1;
			}
			++c;
		}
		else if (prctl(PR_CAPBSET_DROP, i, 0, 0, 0)) {
			if (i > CAP_LAST_CAP)
				break;
			else if (errno == EINVAL) {
				printf("cap not found: %lu\n", i);
				return -1;
			}
			printf("PR_CAPBSET_DROP: %s\n", strerror(errno));
			return -1;
		}
	}
	/* if not requesting any file caps, set no new privs process flag */
	if (!c) {
		if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
			printf("no new privs failed\n");
			return -1;
		}
	}
	if (prctl(PR_SET_SECUREBITS,
			 SECBIT_KEEP_CAPS_LOCKED
			|SECBIT_NO_SETUID_FIXUP
			|SECBIT_NO_SETUID_FIXUP_LOCKED
			|SECBIT_NOROOT
			|SECBIT_NOROOT_LOCKED)) {
		printf("prctl(): %s\n", strerror(errno));
		return -1;
	}
	return 0;
}
