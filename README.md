# jettison
launch programs into a whitelist environment. however, X11 does not support
this type of compartmentalization. window contents/titles, keystrokes,
and whatnot are not be protected on the same X server. if you know of any
other common pieces of software that completely break application sandboxing
on linux, please let me know so i can update this notice.

see configs directory for example pod configuration files.

building + installation:
> make

> su root

> cp jettison /usr/local/bin/jettison

> chmod u+s /usr/local/bin/jettison (setuid bit)

> jettison /bin/bash config.pod --nokill

#config options

##chroot
set the pods new root directory.

##file
this option will make a private bind mount in pod's root.
there are some mount flags we have to specify.
(r)ead (w)rite e(x)ecute (s)uid (d)evice

##home
home is the same as file, except that it will mount the file from current
$HOME path, to <podroot>/podhome

##seccomp
use --nokill option until you have documented exactly which calls the
program makes.  this can be done with strace.

>strace -o outfile -f -s 0 && grep 'ENOSYS' outfile

when you have a working list, you should optimize it. sort by most
frequently made call. strace can generate the list by doing the following

>strace -o outfile -f -c -S calls

you can use seccomp_enumerator to convert outfile to pod options.

>./seccomp_enumerator outfile whitelist

as programs are developed, new systemcalls may be added, so i'm currently
working on a pain-free way to print denied systemcalls using a --tracecalls
option, as well as better tracing support. this is very much a WIP.

##bugs

currently hardcoded for AUDIT_ARCH_I386, you will have to change
this in jettison.c to use other architectures.

##other

please send any feedback, suggestions, bugs, flames, etc
to contact email listed in source files, or through github.
