/* (c) Michael R. Tirado -- GPLv3 -- Gnu General Public License version 3
 *
 * set libc stdio to line buffered mode so we don't miss anything
 * over daemon pipe if --logoutput is specified
 */

#include <errno.h>
#include <string.h>
#include <stdio.h>

__attribute__ ((constructor)) void linebuffer()
{
	errno = 0;
	if (setvbuf(stdout, NULL, _IOLBF, 0)) {
		printf("setvbuf(stdout, NULL, _IOLBUF, 0) failed\n");
		printf("%s\n", strerror(errno));
	}
	else {
		printf("stdio set to line buffer mode.\n");
	}
}






























