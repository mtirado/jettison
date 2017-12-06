/* Copyright (C) 2017 Michael R. Tirado <mtirado418@gmail.com> -- GPLv3+
 *
 * This program is libre software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details. You should have
 * received a copy of the GNU General Public License version 3
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <malloc.h>
#include <time.h>
#include "defines.h"
#include "eslib/eslib.h"
#include "eslib/eslib_fortify.h"
#include "init_cmdr.h"
#include "misc.h"

extern gid_t g_rgid;
extern uid_t g_ruid;
extern struct newnet_param g_newnet;
extern char g_cwd[MAX_SYSTEMPATH];
extern char g_newroot[MAX_SYSTEMPATH];
struct gizmo g_gizmos[NUM_GIZMOS];
struct bg_gizmo *g_bg_gizmos; /* gizmos running in background */

struct bg_gizmo *cmdr_get_bg_gizmos()
{
	return g_bg_gizmos;
}
struct bg_gizmo *cmdr_remove_background_gizmo(pid_t pid)
{
	struct bg_gizmo **trail = &g_bg_gizmos;
	struct bg_gizmo  *bg = g_bg_gizmos;
	while (bg)
	{
		if (bg->pid == pid) {
			*trail = bg->next;
			bg->next = NULL;
			break;
		}
		trail = &bg->next;
		bg = bg->next;
	}
	return bg;
}

void load_gizmos()
{
	struct gizmo *giz = g_gizmos;

	g_bg_gizmos = NULL;
	memset(g_gizmos, 0, sizeof(struct gizmo) * NUM_GIZMOS);

	es_strcopy(giz[0].name, "echo", JETTISON_CMDR_MAXNAME, NULL);
	giz[0].flags |= CMDR_FLAG_UNFORTIFIED;

	es_strcopy(giz[1].name, "sleep", JETTISON_CMDR_MAXNAME, NULL);
	giz[1].flags |= CMDR_FLAG_UNFORTIFIED;

	es_strcopy(giz[2].name, "xtables-multi", JETTISON_CMDR_MAXNAME, NULL);
	giz[2].flags |= CMDR_FLAG_NO_ROOT_NETNS;
	giz[2].flags |= CMDR_FLAG_UNFORTIFIED;
	giz[2].caps[CAP_NET_RAW]   = 1;
	giz[2].caps[CAP_NET_ADMIN] = 1;

	es_strcopy(giz[3].name, "tcpdump", JETTISON_CMDR_MAXNAME, NULL);
	giz[3].flags |= CMDR_FLAG_NO_ROOT_NETNS;
	giz[3].flags |= CMDR_FLAG_BACKGROUND;
	giz[3].flags |= CMDR_FLAG_GIZMODIR;
	giz[3].caps[CAP_NET_RAW]   = 1;

	es_strcopy(giz[4].name, "ls", JETTISON_CMDR_MAXNAME, NULL);
	giz[4].flags |= CMDR_FLAG_HOMEFORT;
}

struct gizmo *cmdr_find_gizmo(char *name, const unsigned int len)
{
	int i;

	if (len >= JETTISON_CMDR_MAXNAME - 1 || len == 0 || name[len] != '\0') {
		printf("gizmo cmdlen error len=%d \n", len);
		return NULL;
	}

	for (i = 0; i < NUM_GIZMOS; ++i)
	{
		if (strncmp(name, g_gizmos[i].name, len+1) == 0) {
			return &g_gizmos[i];
		}
	}

	printf("gizmo not found: %s\n", name);
	return NULL;
}

static int get_exit_status(pid_t pid)
{
	int status = -1;

	while (1)
	{
		pid_t p = waitpid(pid, &status, 0);
		if (p == pid) {
			break;
		}
		else if (p < 0 && errno != EINTR) {
			printf("waitpid(%d) error: %s\n", p, strerror(errno));
			return -1;
		}
	}
	if (WIFEXITED(status)) {
		if (WEXITSTATUS(status)) {
			printf("gizmo(%d) exited with %d\n", pid, WEXITSTATUS(status));
		}
		else {
			return 0; /* success */
		}
	}
	else if (WIFSIGNALED(status)) {
		printf("gizmo(%d) signalled with %d\n", pid, WTERMSIG(status));
	}

	return status;
}

/* create a timestamped dir at cwd for file io */
static char *get_gizmo_dir()
{
	static char giz_dir[MAX_SYSTEMPATH];
	static int once = 0;
	char hexstr[9];
	struct timespec t;
	char *filename;
	char *timestamp;
	int i, r;

	if (once)
		return giz_dir;
	timestamp = get_timestamp();

retry:
	clock_gettime(CLOCK_MONOTONIC_RAW, &t);
	filename = eslib_file_getname(g_newroot);
	if (filename == NULL)
		return NULL;

	if (randhex(hexstr,sizeof(hexstr)-1, ++i + 0x1f2e3d4c + t.tv_nsec+t.tv_sec, 999))
		return NULL;
	hexstr[sizeof(hexstr)-1] = '\0';
	if (es_sprintf(giz_dir,sizeof(giz_dir),NULL, "%s/%s-%s-%s",
				g_cwd, filename, timestamp, hexstr))
		return NULL;

	if (eslib_file_path_check(giz_dir)) {
		printf("bad path: %s\n", giz_dir);
		return NULL;
	}

	setuid(g_ruid);
	setgid(g_rgid);
	r = mkdir(giz_dir, 0750);
	if (r && errno == EEXIST) {
		printf("highly improbable name collision in gizmo dir: %s\n", giz_dir);
		usleep(50000);
		goto retry;
	}
	else if (r) {
		printf("mkdir(%s): %s\n", giz_dir, strerror(errno));
		return NULL;
	}

	if (chmod(giz_dir, 0750)) {
		printf("chmod: %s\n", strerror(errno));
		return NULL;
	}
	if (chown(giz_dir, g_ruid, g_rgid)) {
		printf("chown: %s\n", strerror(errno));
		return NULL;
	}

	setuid(0);
	setgid(0);

	once = 1;
	return giz_dir;
}

static int create_gizmodir(struct gizmo *giz, char *outbuf, size_t bufsize)
{
	char *giz_dir;

	giz_dir = get_gizmo_dir();
	if (giz_dir == NULL)
		return -1;
	if (es_sprintf(outbuf, bufsize, NULL, "%s/%s", giz_dir, giz->name))
		return -1;
	if (eslib_file_path_check(outbuf)) {
		printf("bad logdir: %s\n", outbuf);
		return -1;
	}

	setuid(g_ruid);
	setgid(g_rgid);

	if (mkdir(outbuf, 0750) && errno != EEXIST) {
		printf("mkdir(%s): %s\n", outbuf, strerror(errno));
		return -1;
	}

	if (chmod(outbuf, 0750)) {
		printf("chmod: %s\n", strerror(errno));
		return -1;
	}
	if (chown(outbuf, g_ruid, g_rgid)) {
		printf("chown: %s\n", strerror(errno));
		return -1;
	}

	setuid(0);
	setgid(0);

	return 0;
}


static int cmdr_fortify_gizroot(struct gizmo *giz)
{
	char gizroot[MAX_SYSTEMPATH];
	char gizmodir[MAX_SYSTEMPATH];
	char binpath[MAX_SYSTEMPATH];
	struct path_node node;
	unsigned int fortflags =  ESLIB_FORTIFY_SHARE_NET
				| ESLIB_FORTIFY_IGNORE_CAP_BLACKLIST;

	if (es_sprintf(gizroot, sizeof(gizroot), NULL, "%s/.gizmo", POD_PATH))
		return -1;

	if (es_sprintf(binpath, sizeof(binpath), NULL, "%s/%s",
				JETTISON_CMDR_GIZMOS, giz->name))
		return -1;

	if (giz->flags & CMDR_FLAG_GIZMODIR) {
		if (create_gizmodir(giz, gizmodir, sizeof(gizmodir)))
			return -1;
	}
	memset(&node, 0, sizeof(node));
	node.mntflags = MS_RDONLY|MS_NODEV|MS_UNBINDABLE|MS_NOSUID;

	if (eslib_fortify_prepare(gizroot, 0, fortflags)) {
		printf("fortify failed\n");
		return -1;
	}

	if (setregid(g_rgid, 0))
		return -1;
	if (setreuid(g_ruid, 0))
		return -1;

	/* TODO add define for setting specific gizmo runtime paths */
	if (eslib_fortify_install_file(gizroot, binpath, node.mntflags,
				ESLIB_BIND_CREATE | ESLIB_BIND_PRIVATE))
		return -1;
	if (eslib_fortify_install_file(gizroot, "/lib", node.mntflags,
				ESLIB_BIND_CREATE | ESLIB_BIND_PRIVATE))
		return -1;
	if (eslib_fortify_install_file(gizroot, "/usr/lib", node.mntflags,
				ESLIB_BIND_CREATE | ESLIB_BIND_PRIVATE))
		return -1;

	if (giz->flags & CMDR_FLAG_GIZMODIR) {
		/* /gizmo */
		node.mntflags = MS_NOEXEC|MS_NODEV|MS_NOSUID;
		if (es_strcopy(node.src, gizmodir, MAX_SYSTEMPATH, NULL))
			return -1;
		if (es_sprintf(node.dest,MAX_SYSTEMPATH,NULL,"%s/%s", gizroot, "gizmo"))
			return -1;
		eslib_file_mkdirpath(node.dest, 0755);
		if (setreuid(0, g_ruid))
			return -1;
		if (pathnode_bind(&node))
			return -1;
	}

	if (setreuid(g_ruid, 0))
		return -1;

	if (giz->flags & CMDR_FLAG_HOMEFORT) {
		char *home = gethome(g_ruid);
		if (home == NULL)
			return -1;
		/* mount users home */
		if (eslib_fortify_install_file(gizroot, home, node.mntflags,
				ESLIB_BIND_CREATE | ESLIB_BIND_PRIVATE))
			return -1;
		/* /podhome */
		if (es_sprintf(node.src, MAX_SYSTEMPATH,NULL, "%s/podhome", g_newroot))
			return -1;
		if (es_sprintf(node.dest,MAX_SYSTEMPATH,NULL, "%s/podhome", gizroot))
			return -1;
		eslib_file_mkdirpath(node.dest, 0755);
		if (pathnode_bind(&node))
			return -1;
	}

	/* TODO syscall filters ?  */
	if (eslib_fortify(gizroot, 0,0, NULL,
				  giz->caps,giz->caps,giz->caps,giz->caps, fortflags)) {
		printf("fortify failed\n");
		return -1;
	}

	if (setreuid(0, g_ruid))
		return -1;

	if (giz->flags & CMDR_FLAG_GIZMODIR) {
		if (chdir("/gizmo")) {
			printf("chdir(/gizmo): %s\n", strerror(errno));
			return -1;
		}
	}
	return 0;
}

/* handle flags before forking new process */
static int cmdr_flags_prefork(struct gizmo *giz)
{
	if (giz->flags & CMDR_FLAG_NO_ROOT_NETNS) {
		if (!g_newnet.active) {
			printf("cannot use gizmo(%s) in root net namespace\n", giz->name);
			return -1;
		}
	}

	if (giz->flags & CMDR_FLAG_UNFORTIFIED) {
		if (giz->flags & (CMDR_FLAG_HOMEFORT | CMDR_FLAG_GIZMODIR)) {
			printf("gizmo cannot be unfortified with homefort or gizmodir\n");
			return -1;
		}
	}
	else {
		if (giz->flags & CMDR_FLAG_GIZMODIR) {
			get_gizmo_dir(); /* get path once before forking */
		}
	}
	return 0;
}

/* handle flags after forking new process */
static int cmdr_flags_postfork(struct gizmo *giz)
{

	if (giz->flags & CMDR_FLAG_UNFORTIFIED) {
	        if (setresuid(g_ruid, 0, g_ruid)) {
			printf("error setting uid(%d): %s\n", g_ruid, strerror(errno));
			return -1;
		}
		if (setresgid(g_rgid, g_rgid, g_rgid)) {
			printf("error setting gid(%d): %s\n", g_rgid, strerror(errno));
			return -1;
		}
		if (set_caps(giz->caps, giz->caps, giz->caps, giz->caps, 1)) {
			printf("set_caps error\n");
			return -1;
		}
		if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
			printf("could not set no new privs:%s\n", strerror(errno));
			return -1;
		}
	}
	else {
		if (cmdr_fortify_gizroot(giz)) {
			printf("fortify_gizroot failed\n");
			return -1;
		}
		if (setresuid(g_ruid, 0, g_ruid)) {
			printf("error setting uid(%d): %s\n", g_ruid, strerror(errno));
			return -1;
		}
		if (setresgid(g_rgid, g_rgid, g_rgid)) {
			printf("error setting gid(%d): %s\n", g_rgid, strerror(errno));
			return -1;
		}
	}
	return 0;
}

static int close_fds(int in, int out, int err)
{
	int fdexempt[3] = { STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO };
	if (in >= 0 && dup2(in, STDIN_FILENO) != STDIN_FILENO)
		return -1;
	if (out >= 0 && dup2(out, STDOUT_FILENO) != STDOUT_FILENO)
		return -1;
	if (err >= 0 && dup2(err, STDERR_FILENO) != STDERR_FILENO)
		return -1;
	if (close_descriptors(fdexempt, 3))
		return -1;
	return 0;
}
#include <stdlib.h>
#include <dirent.h>
static int execute(struct gizmo *giz, char *argv[], char *username, char *home)
{
	char binpath[MAX_SYSTEMPATH];
	char env_username[MAX_SYSTEMPATH];
	char env_logname[MAX_SYSTEMPATH];
	char env_home[MAX_SYSTEMPATH];
	char *env[4] = { NULL, NULL, NULL, NULL };
	pid_t p;
	int devnull;

	/* setup program environ variables */
	if (username == NULL || home == NULL)
		return -1;
	if (es_sprintf(env_home, sizeof(env_home), NULL, "HOME=%s", home))
		return -1;
	if (es_sprintf(env_username, sizeof(env_username), NULL, "USER=%s", username))
		return -1;
	if (es_sprintf(env_logname, sizeof(env_logname), NULL, "LOGNAME=%s", username))
		return -1;
	if (es_sprintf(binpath, sizeof(binpath), NULL, "%s/%s",
				JETTISON_CMDR_GIZMOS, giz->name))
		return -1;

	env[0] = env_username;
	env[1] = env_logname;
	env[2] = env_home;
	env[3] = NULL;

	if (cmdr_flags_prefork(giz))
		return -1;

	p = fork();
	if (p < 0) {
		printf("fork(): %s\n", strerror(errno));
		return -1;
	}
	else if (p) {
		if (giz->flags & CMDR_FLAG_BACKGROUND) {
			struct bg_gizmo *bg = calloc(1, sizeof(struct bg_gizmo));
			if (bg == NULL) {
				kill(p, SIGKILL);
				return -1;
			}
			bg->giz = giz;
			bg->pid = p;
			bg->next = g_bg_gizmos;
			g_bg_gizmos = bg;
			return 0;
		}
		else
			return get_exit_status(p);
	}


	/* TODO stdio flags */
	devnull = open("/dev/null", O_RDONLY, 0);
	if (devnull < 0)
		close(0);
	if (close_fds(devnull, -1, -1))
		return -1;
	if (cmdr_flags_postfork(giz))
		return -1;
	if (execve(binpath, argv, env) < 0) {
		printf("execv failure: %s\n", strerror(errno));
		return -1;
	}
	return 0;
}

static int cmdr_command(char *line, const unsigned int linelen,char *username,char *home)
{
	char name[32];
	char *argv[JETTISON_CMDR_MAXARGS+1];
	unsigned short argc = 0;
	char *cmd = NULL;
	char *token = NULL;
	struct gizmo *giz = NULL;
	unsigned int advance = 0;
	unsigned int linepos = 0;
	unsigned int cmdlen = 0;
	memset(argv, 0, sizeof(argv));

	cmd = eslib_string_toke(line, linepos, linelen, &advance);
	if (!cmd) {
		return 0;
	}
	linepos += advance;

	cmdlen = strnlen(cmd, JETTISON_CMDR_MAXNAME);
	giz = cmdr_find_gizmo(cmd, strnlen(cmd, cmdlen));
	if (giz == NULL) {
		printf("unknown gizmo: (%s)\n", cmd);
		return -1;
	}
	if (!giz->executable) {
		printf("missing permission for gizmo: %s\n", cmd);
		return -1;
	}
	if (es_sprintf(name, sizeof(name), NULL, "gizmo-%s", cmd))
		return -1;

	argv[argc++] = name;
	do {
		token = eslib_string_toke(line, linepos, linelen, &advance);
		linepos += advance;
		if (token) {
			argv[argc++] = token;
			if (argc >= JETTISON_CMDR_MAXARGS) {
				printf("max arguments:  %d\n", JETTISON_CMDR_MAXARGS);
				return -1;
			}
		}
	} while (token);

	if (execute(giz, argv, username, home)) {
		printf("failed to execute command: %s\n", giz->name);
		return -1;
	}
	return 0;
}

int cmdr_launch(char *fbuf, const size_t flen, char *username, char *home)
{
	size_t fpos = 0;
	if (flen >= JETTISON_CMDR_LIMIT)
		return -1;

	while (fpos < flen)
	{
		char *line = &fbuf[fpos];
		unsigned int linelen = 0;

		linelen = eslib_string_linelen(line, flen - fpos);
		if (linelen >= flen - fpos) {
			return -1;
		}
		else if (linelen == 0) {
			++fpos;
			continue;
		}
		if (line[0] == '#') {
			fpos += linelen + 1;
			continue;
		}

		if (!eslib_string_is_sane(line, linelen))
			return -1;
		if (eslib_string_tokenize(line, linelen, " \t"))
			return -1;

		if (cmdr_command(line, linelen, username, home)) {
			printf("command(%s) failed\n", line);
			return -1;
		}

		fpos += linelen + 1;
		if (fpos == flen)
			break;
		else if (fpos > flen)
			return -1;
	}
	return 0;
}

int init_cmdr(char *name)
{
	char path[MAX_SYSTEMPATH];
	char home[MAX_SYSTEMPATH-10];
	char username[40];
	char *passwd;
	char *passwd_field;
	char *fbuf;
	size_t flen;
	int r;

	if (name[0] == '\0')
		return 0;

	memset(username, 0, sizeof(username));
	memset(home, 0, sizeof(home));
	passwd = passwd_fetchline_byid(g_ruid, PASSWD_FILE);
	if (passwd == NULL) {
		printf("could not open /etc/passwd for username\n");
		return -1;
	}

	passwd_field = passwd_getfield(passwd, PASSWD_USER);
	if (passwd_field == NULL) {
		printf("bad passwd username\n");
		return -1;
	}
	if (es_strcopy(username, passwd_field, sizeof(username), NULL))
		return -1;

	passwd_field = passwd_getfield(passwd, PASSWD_HOME);
	if (passwd_field == NULL) {
		printf("bad passwd home\n");
		return -1;
	}
	if (es_strcopy(home, passwd_field, sizeof(home), NULL))
		return -1;

	if (strnlen(name, JETTISON_CMDR_MAXNAME) >= JETTISON_CMDR_MAXNAME) {
		printf("cmdr name too long\n");
		return -1;
	}
	if (es_sprintf(path, sizeof(path), NULL, "%s/%s/%s",
				JETTISON_CMDRS, username, name))
		return -1;

	fbuf = load_text_file(path, JETTISON_CMDR_LIMIT, &flen);
	if (fbuf == NULL) {
		printf("couldn't open file: %s\n", path);
		return -1;
	}

	r = cmdr_launch(fbuf, flen, username, home);
	free(fbuf);
	return r;
}

