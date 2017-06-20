#TODO there are more useful defines to make visible here
ifndef DESTDIR
DESTDIR=/usr/local
endif
ifndef PREFIX
PREFIX=/usr/local
endif
ifndef MANDIR
MANDIR=/share/man
endif
ifndef POD_PATH
POD_PATH="/opt/pods"
endif
ifndef STOCKPOD_PATH
STOCKPOD_PATH="/etc/jettison/pods"
endif
ifndef JETTISON_PATH
JETTISON_PATH="/bin/jettison"
endif
ifndef INIT_PATH
INIT_PATH="/bin/jettison_init"
endif
ifndef PRELOAD_PATH
PRELOAD_PATH="/bin/jettison_preload.so"
endif
ifndef DESTRUCT_PATH
DESTRUCT_PATH="/bin/jettison_destruct"
endif
ifndef DEF_UID
DEF_UID=1000
endif

# defines go after CFLAGS
DEFINES := 						\
	-DMAX_SYSTEMPATH=1024 				\
	-D_FILE_OFFSET_BITS=64				\
	-DDEFAULT_STACKSIZE=4194304			\
	-DPOD_PATH=\"$(POD_PATH)\"			\
	-DSTOCKPOD_PATH=\"$(STOCKPOD_PATH)\"		\
	-DINIT_PATH=\"$(PREFIX)$(INIT_PATH)\"		\
	-DPRELOAD_PATH=\"$(PREFIX)$(PRELOAD_PATH)\"

##############################################################################
# optional features
##############################################################################

# support file capabilities (possibly dangerous, not advised for untrusted users)
#DEFINES += -DUSE_FILE_CAPS
# only read pod config files from stock directoy /etc/jettison/pods
#DEFINES += -DSTOCK_PODS_ONLY
#for X11 auth support
#DEFINES += -DX11OPT
#JETTISON_LIBS := -lXau

# for system building, this should NEVER be compiled with capabilities enabled
#DEFINES += -DPODROOT_HOME_OVERRIDE

# newnet namespace device hookups
# these options require control of network resources. ip address,
# mac address, etc. these resources are protected by
# users permission file located at /etc/jettison/users/<user>
# underlying drivers may be new; ipvlan requires ipv6.
# TODO veth bridge and even more possiblities
DEFINES += -DNEWNET_IPVLAN
DEFINES += -DNEWNET_MACVLAN


##############################################################################
CFLAGS  := -pedantic -Wall -Wextra -Werror
DEFLANG := -ansi
#DBG	:= -g

#TODO strip debugging info from binaries

#########################################
#	PROGRAM SOURCE FILES
#########################################
JETTISON_SRCS :=					\
		./src/jettison.c			\
		./src/pod.c				\
		./src/misc.c				\
		./src/util/netns_helper.c		\
		./src/eslib/eslib_file.c		\
		./src/eslib/eslib_sock.c		\
		./src/eslib/eslib_proc.c		\
		./src/eslib/eslib_log.c			\
		./src/eslib/eslib_rtnetlink.c		\
		./src/eslib/eslib_fortify.c		\
		./src/util/tracecalls.c
JETTISON_OBJS := $(JETTISON_SRCS:.c=.o)

DESTRUCT_SRCS :=					\
		./src/misc.c				\
		./src/destruct.c			\
		./src/eslib/eslib_proc.c
DESTRUCT_OBJS := $(DESTRUCT_SRCS:.c=.o)


INIT_SRCS :=	./src/jettison_init.c			\
		./src/eslib/eslib_file.c		\
		./src/eslib/eslib_proc.c
INIT_OBJS := $(INIT_SRCS:.c=.o)

########################################
#	PROGRAM FILENAMES
########################################
JETTISON		:= jettison
DESTRUCT		:= jettison_destruct
INIT	  		:= jettison_init
UTIL_PRELOAD		:= jettison_preload.so

%.o: 		%.c
			$(CC) -c $(DEFLANG) $(CFLAGS) $(DEFINES) $(DBG) -o $@ $<

all:				\
	$(JETTISON)		\
	$(DESTRUCT)		\
	$(UTIL_SECCOMP_ENUM)	\
	$(UTIL_PRELOAD)		\
	$(INIT)

install:
	@umask 022
	@echo $(DESTDIR)/$(POD_PATH)
	@install -dvm 0755  "$(DESTDIR)/$(POD_PATH)"
	@install -dvm 0770  "$(DESTDIR)/$(POD_PATH)/user"
	@install -dvm 0755  "$(DESTDIR)/$(STOCKPOD_PATH)"
	@install -Dvm 04655 "$(JETTISON)" "$(DESTDIR)/$(JETTISON_PATH)"
	@install -Dvm 02655 "$(DESTRUCT)" "$(DESTDIR)/$(DESTRUCT_PATH)"
	@install -Dvm 0655  "$(INIT)"     "$(DESTDIR)/$(INIT_PATH)"
	@install -Dvm 0655  "$(UTIL_PRELOAD)"  "$(DESTDIR)/$(PRELOAD_PATH)"
	@install -DCvm 0644  etc/jettison/users/user "$(DESTDIR)/etc/jettison/users/user"
	@install -DCvm 0644  etc/jettison/blacklist "$(DESTDIR)/etc/jettison/blacklist"
	@install -Dvm 0644   man/jettison.1 \
				"$(DESTDIR)/$(MANDIR)/man1/jettison.1"
	@install -Dvm 0644   man/jettison_destruct.8 \
				"$(DESTDIR)/$(MANDIR)/man8/jettison_destruct.8"
#	@chown   -v 0:0 $(DESTDIR)/$(POD_PATH)
#	@chown   -v$(DEF_UID):0 $(DESTDIR)/$(POD_PATH)/user
clean:
	@$(foreach obj, $(JETTISON_OBJS), rm -fv $(obj);)
	@$(foreach obj, $(DESTRUCT_OBJS), rm -fv $(obj);)
	@$(foreach obj, $(INIT_OBJS),     rm -fv $(obj);)

	@-rm -fv ./$(JETTISON)
	@-rm -fv ./$(DESTRUCT)
	@-rm -fv ./$(UTIL_PRELOAD)
	@-rm -fv ./$(INIT)
	@echo cleaned.


########################################
#	BUILD TARGETS
########################################
$(JETTISON):		$(JETTISON_OBJS)
			$(CC) $(LDFLAGS) $(JETTISON_LIBS) $(JETTISON_OBJS) -o $@
			@echo ""
			@echo "x------------------x"
			@echo "| jettison      OK |"
			@echo "x------------------x"
			@echo ""

$(DESTRUCT):		$(DESTRUCT_OBJS)
			$(CC) $(LDFLAGS) $(DESTRUCT_OBJS) -o $@
			@echo ""
			@echo "x--------------------x"
			@echo "| destruct        OK |"
			@echo "x--------------------x"
			@echo ""

$(INIT):		$(INIT_OBJS)
			$(CC) $(LDFLAGS) $(INIT_OBJS) -o $@
			@echo ""
			@echo "x--------------------x"
			@echo "| util: init      OK |"
			@echo "x--------------------x"
			@echo ""

$(UTIL_PRELOAD):
			@echo ""
			$(CC) $(CFLAGS) $(DEFLANG) $(DEFINES) -shared -o $@ -fPIC \
					./src/util/jettison_preload.c
			@echo ""
			@echo "x--------------------x"
			@echo "| util: preload   OK |"
			@echo "x--------------------x"
			@echo ""
