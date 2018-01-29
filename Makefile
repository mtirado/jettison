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
POD_PATH=/opt/pods
endif
ifndef STOCKPOD_PATH
STOCKPOD_PATH=/etc/jettison/pods
endif
ifndef JETTISON_PATH
JETTISON_PATH=/bin/jettison
endif
ifndef INIT_PATH
INIT_PATH=/bin/jettison_init
endif
ifndef PRELOAD_PATH
PRELOAD_PATH=/bin/jettison_preload.so
endif
ifndef DESTRUCT_PATH
DESTRUCT_PATH=/bin/jettison_destruct
endif
ifndef DEF_UID
DEF_UID=1000
endif

# defines go after CFLAGS
CDEFINES := 						\
	-DMAX_SYSTEMPATH=1024 				\
	-D_FILE_OFFSET_BITS=64				\
	-DDEFAULT_STACKSIZE=4194304			\
	-DPOD_PATH=\"$(POD_PATH)\"			\
	-DSTOCKPOD_PATH=\"$(STOCKPOD_PATH)\"		\
	-DINIT_PATH=\"$(PREFIX)$(INIT_PATH)\"		\
	-DPRELOAD_PATH=\"$(PREFIX)$(PRELOAD_PATH)\"


JETTISON_LIBS :=
OPTIONAL_OBJS :=
##############################################################################
# optional features
##############################################################################

# support file capabilities (possibly dangerous, not advised for untrusted users)
#CDEFINES += -DUSE_FILE_CAPS

# only read pod config files from stock directory /etc/jettison/pods
#CDEFINES += -DSTOCK_PODS_ONLY

#for X11 auth support
#CDEFINES += -DX11OPT
#JETTISON_LIBS += -lXau

# for system building, this should NEVER be compiled with capabilities enabled
#CDEFINES += -DPODROOT_HOME_OVERRIDE

CDEFINES  += -DPOD_INIT_CMDR
OPTIONAL_OBJS += ./src/init_cmdr.c

# newnet namespace device hookups
# these options require control of network resources. ip address,
# mac address, etc. these resources are protected by
# users permission file located at /etc/jettison/users/<user>
# underlying drivers may be new; ipvlan requires ipv6.
# TODO veth bridge and even more possiblities
CDEFINES += -DNEWNET_IPVLAN
CDEFINES += -DNEWNET_MACVLAN


##############################################################################
# CC arguments
##############################################################################
CLANG   := -ansi
CFLAGS  := -pedantic -Wall -Wextra -Wconversion -Werror $(CLANG) $(CDEFINES)
LDFLAGS := $(JETTISON_LIBS)

#TODO strip debugging info from binaries

#########################################
# source and object files
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
		./src/eslib/eslib_string.c		\
		./src/util/tracecalls.c			\
		$(OPTIONAL_OBJS)
JETTISON_OBJS := $(JETTISON_SRCS:.c=.o)

DESTRUCT_SRCS :=					\
		./src/misc.c				\
		./src/destruct.c			\
		./src/eslib/eslib_file.c		\
		./src/eslib/eslib_string.c		\
		./src/eslib/eslib_proc.c
DESTRUCT_OBJS := $(DESTRUCT_SRCS:.c=.o)


INIT_SRCS :=	./src/jettison_init.c			\
		./src/eslib/eslib_file.c		\
		./src/eslib/eslib_string.c		\
		./src/eslib/eslib_proc.c
INIT_OBJS := $(INIT_SRCS:.c=.o)

########################################
# output filenames
########################################
JETTISON		:= jettison
DESTRUCT		:= jettison_destruct
INIT	  		:= jettison_init
UTIL_PRELOAD		:= jettison_preload.so

########################################
# make targets
########################################
%.o: 		%.c
			$(CC) -c $(CFLAGS) -o $@ $<

all:				\
	$(JETTISON)		\
	$(DESTRUCT)		\
	$(UTIL_SECCOMP_ENUM)	\
	$(UTIL_PRELOAD)		\
	$(INIT)

install:
	@echo $(DESTDIR)/$(POD_PATH)
	@install -dvm  0755  "$(DESTDIR)/$(POD_PATH)"
	@install -dvm  0770  "$(DESTDIR)/$(POD_PATH)/user"
	@install -dvm  0755  "$(DESTDIR)/$(STOCKPOD_PATH)"
	@install -Dvm  04755 "$(JETTISON)" "$(DESTDIR)/$(JETTISON_PATH)"
	@install -Dvm  02755 "$(DESTRUCT)" "$(DESTDIR)/$(DESTRUCT_PATH)"
	@install -Dvm  0655  "$(INIT)"     "$(DESTDIR)/$(INIT_PATH)"
	@install -Dvm  0655  "$(UTIL_PRELOAD)"  "$(DESTDIR)/$(PRELOAD_PATH)"
	@install -DCvm 0644  etc/jettison/users/user "$(DESTDIR)/etc/jettison/users/user"
	@install -DCvm 0644  etc/jettison/blacklist "$(DESTDIR)/etc/jettison/blacklist"
	@install -Dvm  0644   man/jettison.1 \
				"$(DESTDIR)/$(MANDIR)/man1/jettison.1"
	@install -Dvm 0644   man/jettison_destruct.1 \
				"$(DESTDIR)/$(MANDIR)/man8/jettison_destruct.1"
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


$(JETTISON):		$(JETTISON_OBJS)
			$(CC) $(LDFLAGS) $(JETTISON_OBJS) -o $@
			@echo ""
			@echo "x---------------x"
			@echo "| jettison      |"
			@echo "x---------------x"
			@echo ""

$(DESTRUCT):		$(DESTRUCT_OBJS)
			$(CC) $(LDFLAGS) $(DESTRUCT_OBJS) -o $@
			@echo ""
			@echo "x-----------------x"
			@echo "| destruct        |"
			@echo "x-----------------x"
			@echo ""

$(INIT):		$(INIT_OBJS)
			$(CC) $(LDFLAGS) $(INIT_OBJS) -o $@
			@echo ""
			@echo "x-----------------x"
			@echo "| pod init        |"
			@echo "x-----------------x"
			@echo ""

$(UTIL_PRELOAD):
			@echo ""
			$(CC) $(CFLAGS) -shared -o $@ -fPIC ./src/util/jettison_preload.c
			@echo ""
			@echo "x-----------------x"
			@echo "| util: preload   |"
			@echo "x-----------------x"
			@echo ""
