# jettison
launch programs into a whitelist environment. however, X11 users must take
extra care to adequately compartmentalize a pod. You should start a new X11
session for applications that can not be trusted with sharing keystrokes
and screen contents, possible window control, inject input, etc...
this can be accomplished by simply running startx in a new getty virtual terminal.
switch between sessions using ctrl-alt f7,f8,f9 and so forth. any pods that wish
to connect to X11 must specify the X11 option to copy auth data and /tmp socket,
for the current $DISPLAY environ var. `startx -- -nolisten local -nolisten tcp`
will tell X to not listen in abstract socket namespace, or tcp socket. which is
ideal to prevent a hostile pod from even attempting to cross X11 sessions.


see configs directory for example pod configuration files.
this has only been tested on x86 using AUDIT_ARCH_I386. i have not explored
other arch's at all yet, so you may have to change this in jettison.c


##building + installation:
```
#initialize eslib
git submodule update --init --recursive

#or update eslib
git submodule update --remote

make

su root

cp ./{jettison,jettison_init,jettison_preload.so,jettison_destruct} /usr/local/bin/

#setuid bit
chmod u+s /usr/local/bin/jettison

#setgid bit
chmod g+s /usr/local/bin/jettison_destruct

mkdir /opt/pods
```

##usage

two arguments must be included. first is the program path which must be

an absolute path,  second is the pod configuration file. the config file

name is used as the chroot directory at /opt/pods/user/cfg.pod

all files here are root owned, except for /podhome


usage:
`jettison /bin/bash config.pod`

there are additional options we can pass:

`--procname, -p <name>` set process name (argv[0])

`--stacksize <size>` set program stack max

`--tracecalls` track every systemcall and generate whitelist

`--strict` kill process instead of returning error ENOSYS

`--block-new-filters` prevent additional seccomp ilters form being installed

`--allow-ptrace` whitelist ptrace (otherwise it's always blacklisted)

`--daemon` orphan process without a tty

`--logoutput` write stdio to logfile, daemon stdio will use a pipe


use jettison_destruct to clean up pods. since they are root owned
we will need group write permission. (setgid bit)


#pod configuration

##file
this option will make a slave mount in pod's root.

there are some mount flags we have to specify:

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
use capability to specify which file capabilities should be added to bounding set

`capability CAP_NET_RAW`  or any non-blacklisted cap from \<linux/capablilitiy.h\>

a program will need (s)uid option to gain capability on exec

##netns
`netns none` empty network namespace

`netns loop` empty with loopback set up

`netns ipvlan <device> <addr>` create new ipvlan from master device and static address

##noproc
disable /proc filesystem

##home_exec
if $HOME is not whitelisted /podhome is remounted as an empty node

with rw flags. using home_exec will change this to rwx flags.

##X11
X11 option indicates the user will be connecting to X11, copies current display

auth data to /podhome/.Xauthority. also bind mounts display socket to /tmp

for best separation combine with newnet or tell your xserver to NOT listen

in abstract socket namespace.

##bugs
currently only tested using i386.


syscall and cap table can be found in src/util/seccomp_helper.c

depending on your kernel you may need to add/remove entries.

if you see a ton of compiler errors, this is likely the culprit.



##other

please send any feedback, suggestions, bugs, flames, etc

to contact email listed in source files, or through github.
