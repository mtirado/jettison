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
#include <malloc.h>
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

	es_sprintf(giz[0].name, sizeof(giz[0].name), NULL, "echo");
	es_sprintf(giz[1].name, sizeof(giz[1].name), NULL, "sleep");
	es_sprintf(giz[2].name, sizeof(giz[2].name), NULL, "xtables-multi");
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


	fbuf = malloc(4096);
	if (fbuf == NULL)
		return -1;
	if (eslib_file_read_full(path, fbuf, 4096 - 1, &flen)) {
		if (errno == EOVERFLOW) {
			fbuf = realloc(fbuf, flen + 1);
			if (fbuf == NULL)
				return -1;
		}
		else {
			free(fbuf);
		}
		return -1;
	}
	fbuf[flen] = '\0';

	r = cmdr_launch(fbuf, flen, username, home);
	free(fbuf);
	return r;
}

