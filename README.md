# jettison
launch programs into a whitelist environment. however, X11 does not support
this type of compartmentalization. window contents/titles, keystrokes,
and whatnot are not be protected on the same X server. if you know of any
other common pieces of software that completely break application sandboxing
on linux, please let me know so i can update this notice.

see configs directory for example pod configuration files.

this has only been tested on x86 using AUDIT_ARCH_I386. i have not explored
other arch's at all yet, so you may have to change this in jettison.c

building + installation:
```
git submodule update --init --recursive

make

su root

cp ./{jettison,jettison_init,jettison_preload.so} /usr/local/bin/

chmod u+s /usr/local/bin/jettison (setuid bit)

mkdir /opt/pods
```

##usage

two arguments must be included. first is the program path which must be
an absolute path,  second is the pod configuration file.
the config file name is used as the chroot directory at /opt/pods/user/cfg.pod
all files here are root owned, except for /podhome and /tmp


usage:
`jettison /bin/bash config.pod`

there are additional options we can pass:

`--procname <name>` set process name (argv[0])

`--stacksize <size>` set program stack max

`--tracecalls` track every systemcall and generate whitelist

`--strict` kill process instead of returning error ENOSYS

`--block-new-filters` prevent additional seccomp ilters form being installed

`--allow-ptrace` whitelist ptrace (otherwise it's always blacklisted)

`--daemon` orphan process without a tty

`--logoutput` write stdio to logfile, daemon stdio will use a pipe

#pod configuration

##file
this option will make a private bind mount in pod's root.
there are some mount flags we have to specify.
(r)ead (w)rite e(x)ecute (s)uid (d)evice

##home
home is the same as file, except that it will mount the file from current
$HOME path, to <podroot>/podhome

##seccomp
use --tracecalls to track every system call made and generate an optimized
whitelist at ./podtemplate.pod  .  if you have a configuration file already
with no systemcalls you can simply do `cat podtemplate.pod >> config.pod`
to append the whitelist to the configuration file.


##capabilities
use cap_bset to specify which file capabilities should be added to bounding set

`cap_bset CAP_NET_RAW`  or any non-blacklisted cap from <linux/capablilitiy.h>


##bugs

currently hardcoded for AUDIT_ARCH_I386, you will have to change
this in jettison.c to use other architectures.

##other


please send any feedback, suggestions, bugs, flames, etc
to contact email listed in source files, or through github.
