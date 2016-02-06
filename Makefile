# some global defines
DEFINES := 				\
	-DMAX_SYSTEMPATH=2048 		\
	-DDEFAULT_STACKSIZE=4194304	\
	-DPOD_PATH=\"/opt/pods\"	\
	-DTRACEE_PATH=\"/usr/local/bin/jettison_tracee\"

CFLAGS  := -pedantic -Wall -Wextra -Werror $(DEFINES)
#-rdynamic: backtrace names
#LDFLAGS := -rdynamic
DEFLANG	:= -ansi
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
		./src/eslib/eslib_file.c		\
		./src/eslib/eslib_sock.c		\
		./src/util/tracecalls.c
JETTISON_OBJS := $(JETTISON_SRCS:.c=.o)


########################################
#	TESTS
########################################
TEST_SECCOMP_SRCS := 					\
		./src/tests/seccomp_test.c		\
		./src/util/seccomp_helper.c
TEST_SECCOMP_OBJS := $(TEST_SECCOMP_SRCS:.c=.o)
########################################
TEST_SECCOMP_LAUNCH_SRCS := 				\
		./src/tests/seccomp_test_launcher.c	\
		./src/util/seccomp_helper.c
TEST_SECCOMP_LAUNCH_OBJS := $(TEST_SECCOMP_LAUNCH_SRCS:.c=.o)







########################################
#	PROGRAM FILENAMES
########################################
JETTISON		:= jettison
UTIL_TRACEE  		:= jettison_tracee
#tests
TEST_SECCOMP		:= seccomp_test
TEST_SECCOMP_LAUNCH 	:= seccomp_test_launcher

%.o: 		%.c
			$(CC) -c $(DEFLANG) $(CFLAGS) $(DBG) -o $@ $<


all:				\
	$(JETTISON)		\
	$(UTIL_SECCOMP_ENUM)	\
	$(UTIL_TRACEE)

tests:				\
	$(TEST_SECCOMP)		\
	$(TEST_SECCOMP_LAUNCH)


########################################
#	BUILD TARGETS
########################################
$(JETTISON):		$(JETTISON_OBJS)
		  	$(CC) $(LDFLAGS) $(JETTISON_OBJS) -o $@
			@echo ""
			@echo "x------------------x"
			@echo "| jettison      OK |"
			@echo "x------------------x"

$(TEST_SECCOMP):	$(TEST_SECCOMP_OBJS)
		  	$(CC) $(LDFLAGS) $(TEST_SECCOMP_OBJS) -o $@
			@echo ""
			@echo "x-------------------------x"
			@echo "| test: seccomp_test   OK |"
			@echo "x-------------------------x"

$(TEST_SECCOMP_LAUNCH):	$(TEST_SECCOMP_LAUNCH_OBJS)
		  	$(CC) $(LDFLAGS) $(TEST_SECCOMP_LAUNCH_OBJS) -o $@
			@echo ""
			@echo "x----------------------------------x"
			@echo "| test:  seccomp_test_launcher  OK |"
			@echo "x----------------------------------x"

$(UTIL_TRACEE):
			@echo ""
			$(CC) $(CFLAGS) 				\
					./src/util/tracee.c 		\
					./src/eslib/eslib_sock.c 	\
					./src/eslib/eslib_file.c	\
					-o $@
			@echo ""
			@echo "x--------------------x"
			@echo "| util: tracee    OK |"
			@echo "x--------------------x"
			@echo ""

########################################
#	CLEAN UP THE MESS
########################################
clean:
	@$(foreach obj, $(JETTISON_OBJS), rm -fv $(obj);)
	@$(foreach obj, $(TEST_SECCOMP_OBJS), rm -fv $(obj);)
	@$(foreach obj, $(TEST_SECCOMP_LAUNCH_OBJS), rm -fv $(obj);)

	@-rm -fv ./$(JETTISON)
	@-rm -fv ./$(TEST_SECCOMP)
	@-rm -fv ./$(TEST_SECCOMP_LAUNCH)
	@-rm -fv ./$(UTIL_SECCOMP_ENUM)
	@-rm -fv ./$(UTIL_TRACEE)
	@echo cleaned.





