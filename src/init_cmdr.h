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

#define NUM_GIZMOS 3
struct gizmo
{
	char name[JETTISON_CMDR_MAXNAME];
	int  caps[NUM_OF_CAPS];
	unsigned int executable;
};

struct init_cmdr
{
	int fd_gadgets;
	int fd_rootfs;
	int fd_podfs;
};

void load_gizmos();
struct gizmo *cmdr_find_gizmo(char *name, unsigned int len);
int init_cmdr(char *name);

#endif
