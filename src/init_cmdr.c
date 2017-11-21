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
#include "defines.h"
#include "eslib/eslib.h"
#include "eslib/eslib_fortify.h"
#include "init_cmdr.h"
#include "misc.h"

extern gid_t g_rgid;
extern uid_t g_ruid;

struct gizmo g_gizmos[NUM_GIZMOS];
void load_gizmos()
{
	struct gizmo *giz = g_gizmos;
	memset(g_gizmos, 0, sizeof(struct gizmo) * NUM_GIZMOS);

	snprintf(giz[0].name, sizeof(giz[0].name), "echo");
	snprintf(giz[1].name, sizeof(giz[1].name), "sleep");
	snprintf(giz[2].name, sizeof(giz[2].name), "xtables-multi");
	giz[2].caps[CAP_NET_RAW]   = 1;
	giz[2].caps[CAP_NET_ADMIN] = 1;
}

struct gizmo *cmdr_find_gizmo(char *name, const unsigned int len)
{
	int i;

	if (len >= JETTISON_CMDR_MAXNAME || len == 0 || name[len] != '\0') {
		printf("gizmo cmdlen error len=%d \n", len);
		return NULL;
	}

	for (i = 0; i < NUM_GIZMOS; ++i)
	{
		if (strncmp(name, g_gizmos[i].name, len) == 0) {
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

static int execute(struct gizmo *giz, char *argv[], char *username, char *home)
{
	char binpath[MAX_SYSTEMPATH];
	char env_username[MAX_SYSTEMPATH];
	char env_logname[MAX_SYSTEMPATH];
	char env_home[MAX_SYSTEMPATH];
	char *env[4] = { NULL, NULL, NULL, NULL };
	pid_t p;

	/* setup program environ variables */
	if (username == NULL || home == NULL)
		return -1;
	if (snprintf(env_home, sizeof(env_home),
				"HOME=%s", home) >= (int)sizeof(env_home))
		return -1;
	if (snprintf(env_username, sizeof(env_username),
				"USER=%s", username) >= (int)sizeof(env_username))
		return -1;
	if (snprintf(env_logname, sizeof(env_logname),
				"LOGNAME=%s", username) >= (int)sizeof(env_logname))
		return -1;
	if (snprintf(binpath, sizeof(binpath), "%s/%s", JETTISON_CMDR_GIZMOS,
						giz->name) >= (int)sizeof(binpath))
		return -1;

	env[0] = env_username;
	env[1] = env_logname;
	env[2] = env_home;
	env[3] = NULL;

	p = fork();
	if (p < 0) {
		printf("fork(): %s\n", strerror(errno));
		return -1;
	}
	else if (p) {
		return get_exit_status(p);
	}

	/* euid needs to be 0 for caps to be inherited */
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

	if (execve(binpath, argv, env) < 0) {
		printf("execv failure: %s\n", strerror(errno));
		return -1;
	}

	return 0;
}

static int cmdr_command(char *line, const unsigned int linelen, char *username, char *home)
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

	snprintf(name, sizeof(name), "gizmo-%s", cmd);
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

int cmdr_launch(char *instructions, const unsigned int size, char *username, char *home)
{
	unsigned int i = 0;

	while (i < size)
	{
		char *line = &instructions[i];
		unsigned int linelen = 0;

		linelen = eslib_string_linelen(line, size - i);
		if (linelen >= size - i) {
			return -1;
		}
		else if (linelen == 0) {
			++i;
			continue;
		}
		if (line[0] == '#') {
			i += linelen;
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

		i += linelen + 1;
		if (i == size)
			break;
		else if (i > size)
			return -1;
	}
	return 0;
}

static int cmdr_find(char *username, char *name)
{
	char path[MAX_SYSTEMPATH];
	int fd;
	if (strnlen(name, JETTISON_CMDR_MAXNAME) >= JETTISON_CMDR_MAXNAME) {
		printf("cmdr name too long\n");
		return -1;
	}
	if (snprintf(path, sizeof(path), "%s/%s/%s",
				JETTISON_CMDRS, username, name) >= (int)sizeof(path)) {
		return -1;
	}
	fd = open(path, O_RDONLY|O_CLOEXEC);
	if (fd < 0) {
		if (errno == ENOENT)
			printf("missing cmdr: %s\n", path);
		else
			printf("open(%s): %s\n", path, strerror(errno));
		return -1;
	}
	return fd;
}

int init_cmdr(char *name)
{
	char instructions[JETTISON_CMDR_LIMIT+1]; /* + appended '\0' */
	char username[40];
	char home[MAX_SYSTEMPATH-10];
	char *passwd;
	char *passwd_field;
	int fd;
	int r;

	if (name[0] == '\0')
		return 0;

	memset(username, 0, sizeof(username));
	memset(home, 0, sizeof(home));
	passwd = passwd_fetchline(g_ruid);
	if (passwd == NULL) {
		printf("could not open /etc/passwd for username\n");
		return -1;
	}
	passwd_field = passwd_getfield(passwd, PASSWD_USER);
	if (passwd_field == NULL) {
		printf("bad passwd username\n");
		return -1;
	}
	if (snprintf(username, sizeof(username),
				"%s", passwd_field) >= (int)sizeof(username)) {
		return -1;
	}
	passwd_field = passwd_getfield(passwd, PASSWD_HOME);
	if (passwd_field == NULL) {
		printf("bad passwd home\n");
		return -1;
	}
	if (snprintf(home, sizeof(home),
				"%s", passwd_field) >= (int)sizeof(home)) {
		return -1;
	}

	fd = cmdr_find(username, name);
	if (fd < 0) {
		printf("cmdr_init: couldn't open file: %s\n", name);
		return -1;
	}

	memset(instructions, 0, sizeof(instructions));
	r = read(fd, instructions, sizeof(instructions)-1);
	if (r < 0) {
		printf("cmdr_init: read(): %s\n", strerror(errno));
		goto err_close;
	}
	else if (r == 0) {
		printf("cmdr_init: file was empty.\n");
		goto err_close;
	}
	else if (r >= (int)sizeof(instructions)) {
		printf("cmdr_init: file too big (%d/%d)\n", r, sizeof(instructions)-1);
		goto err_close;
	}

	close(fd);
	instructions[r] = '\0';
	return cmdr_launch(instructions, r, username, home);

err_close:
	close(fd);
	return -1;
}

