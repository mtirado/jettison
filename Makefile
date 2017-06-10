# some global defines
DEFINES := 							\
	-DMAX_SYSTEMPATH=2048 					\
	-D_FILE_OFFSET_BITS=64					\
	-DDEFAULT_STACKSIZE=4194304				\
	-DPOD_PATH=\"/opt/pods\"				\
	-DINIT_PATH=\"/usr/local/bin/jettison_init\"		\
	-DPRELOAD_PATH=\"/usr/local/bin/jettison_preload.so\"

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


########################################
#	CLEAN UP THE MESS
########################################
clean:
	@$(foreach obj, $(JETTISON_OBJS), rm -fv $(obj);)
	@$(foreach obj, $(DESTRUCT_OBJS), rm -fv $(obj);)
	@$(foreach obj, $(INIT_OBJS),     rm -fv $(obj);)

	@-rm -fv ./$(JETTISON)
	@-rm -fv ./$(DESTRUCT)
	@-rm -fv ./$(UTIL_PRELOAD)
	@-rm -fv ./$(INIT)
	@echo cleaned.

