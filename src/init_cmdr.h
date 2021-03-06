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

#ifndef INIT_CMDR__
#define INIT_CMDR__

#include "defines.h"

#define NUM_GIZMOS 5

/*
 * notes: gizmodir is shared between invocations of a particular gizmo.
 *        running two of the same gizmos in background could cause issues.
 */
#define CMDR_FLAG_NON_CRITICAL     (1 << 0) /* if something goes wrong, don't freak out */
#define CMDR_FLAG_NO_ROOT_NETNS    (1 << 1) /* do not run in root net namespace */
#define CMDR_FLAG_BACKGROUND       (1 << 2) /* run in background, no error check */
#define CMDR_FLAG_HOMEFORT         (1 << 3) /* fortified with access to home & podhome */
#define CMDR_FLAG_UNFORTIFIED      (1 << 4) /* don't be a fool, fortify your gizmos */
#define CMDR_FLAG_NO_STDOUT        (1 << 5) /* set stdout to /dev/null */
#define CMDR_FLAG_NO_STDERR        (1 << 6) /* set stderr to /dev/null */
#define CMDR_FLAG_GIZMODIR         (1 << 7) /* exec from /gizmo, for file io.
					       mounts to cwd/podname+time/gizmo->name */
struct gizmo
{
	char name[JETTISON_CMDR_MAXNAME];
	int  caps[NUM_OF_CAPS];
	unsigned int executable;
	unsigned int flags;
};

struct bg_gizmo
{
	struct bg_gizmo *next;
	struct gizmo *giz;
	pid_t pid;
};

void load_gizmos();
struct gizmo *cmdr_find_gizmo(char *name, unsigned int len);
int init_cmdr(char *name);
struct bg_gizmo *cmdr_remove_background_gizmo(pid_t pid);
struct bg_gizmo *cmdr_get_bg_gizmos();

#endif
