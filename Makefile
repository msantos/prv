.PHONY: all clean test

PROG=   prv
SRCS=   prv.c \
        getnline.c \
        strtonum.c \
        restrict_process_null.c \
        restrict_process_rlimit.c \
        restrict_process_seccomp.c \
        restrict_process_pledge.c \
        restrict_process_capsicum.c

UNAME_SYS := $(shell uname -s)
ifeq ($(UNAME_SYS), Linux)
    CFLAGS ?= -D_FORTIFY_SOURCE=2 -O2 -fstack-protector-strong \
              -Wformat -Werror=format-security \
              -fno-strict-aliasing
    LDFLAGS ?= -Wl,-z,relro,-z,now -Wl,-z,noexecstack
    RESTRICT_PROCESS ?= seccomp
else ifeq ($(UNAME_SYS), OpenBSD)
    CFLAGS ?= -DHAVE_STRTONUM \
              -D_FORTIFY_SOURCE=2 -O2 -fstack-protector-strong \
              -Wformat -Werror=format-security \
              -fno-strict-aliasing
    LDFLAGS ?= -Wl,-z,relro,-z,now -Wl,-z,noexecstack
    RESTRICT_PROCESS ?= pledge
else ifeq ($(UNAME_SYS), FreeBSD)
    CFLAGS ?= -DHAVE_STRTONUM \
              -D_FORTIFY_SOURCE=2 -O2 -fstack-protector-strong \
              -Wformat -Werror=format-security \
              -fno-strict-aliasing
    LDFLAGS ?= -Wl,-z,relro,-z,now -Wl,-z,noexecstack
    RESTRICT_PROCESS ?= capsicum
endif

RM ?= rm

RESTRICT_PROCESS ?= rlimit
PRV_CFLAGS ?= -g -Wall -fwrapv -pedantic -pie -fPIE
PRV_MAXBUF ?= 8192

CFLAGS += $(PRV_CFLAGS) \
		  -DRESTRICT_PROCESS=\"$(RESTRICT_PROCESS)\" -DRESTRICT_PROCESS_$(RESTRICT_PROCESS) \
			-DPRV_MAXBUF=$(PRV_MAXBUF)

LDFLAGS += $(PRV_LDFLAGS)

all: $(PROG)

$(PROG):
	$(CC) $(CFLAGS) -o $(PROG) $(SRCS) $(LDFLAGS)

clean:
	-@$(RM) $(PROG)

test: $(PROG)
	@PATH=.:$(PATH) bats test
