# some global defines
DEFINES := 							\
	-DUSE_FILE_CAPS						\
	-DMAX_SYSTEMPATH=2048 					\
	-DDEFAULT_STACKSIZE=4194304				\
	-DPOD_PATH=\"/opt/pods\"				\
	-DINIT_PATH=\"/usr/local/bin/jettison_init\"		\
	-DPRELOAD_PATH=\"/usr/local/bin/jettison_preload.so\"

#for X11 auth support
DEFINES += -DX11OPT
JETTISON_LIBS := -lXau

#newnet namespace device hookups. you may want to roll your own if
#allowing random users to run jettison, some of these obtain new net
#resources. ip address, mac address, ip forwarding on a bridge, etc.

# XXX this is experimental right now until we can manage
# network resources (ip/mac addr's) we hand out to user.
DEFINES += -DNEWNET_IPVLAN
DEFINES += -DNEWNET_MACVLAN


CFLAGS  := -pedantic -Wall -Wextra -Werror $(DEFINES)
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
		./src/util/seccomp_helper.c		\
		./src/util/netns_helper.c		\
		./src/eslib/eslib_file.c		\
		./src/eslib/eslib_sock.c		\
		./src/eslib/eslib_proc.c		\
		./src/eslib/eslib_log.c			\
		./src/eslib/eslib_rtnetlink.c		\
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
			$(CC) -c $(DEFLANG) $(CFLAGS) $(DBG) -o $@ $<


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
			$(CC) $(CFLAGS) -shared -o $@ -fPIC 		\
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
	@$(foreach obj, $(INIT_OBJS), rm -fv $(obj);)

	@-rm -fv ./$(JETTISON)
	@-rm -fv ./$(DESTRUCT)
	@-rm -fv ./$(UTIL_PRELOAD)
	@-rm -fv ./$(INIT)
	@echo cleaned.

