#ifndef SECCOMP_HELPER_H__
#define SECCOMP_HELPER_H__

#include <linux/audit.h>
#include <linux/seccomp.h>
#include "../eslib/eslib_fortify.h"
/* TODO move to misc */
int downgrade_caps();
int capbset_drop(int fcaps[NUM_OF_CAPS]);
#endif
