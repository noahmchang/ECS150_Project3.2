# Target library
lib := libfs.a

objs := fs.o disk.o
targets := $(lib)
CC := gcc
CFLAGS := -Wall -Wextra -Werror -std=c99 -MMD -g

ifneq ($(V),1)
Q = @
endif

all: $(lib)

deps := $(patsubst %.o,%.d,$(objs))
-include $(deps)

$(lib): $(objs)
	@echo "AR $@"
	$(Q)ar rcs $@ $^

%.o: %.c
	@echo "CC $@"
	$(Q)$(CC) $(CFLAGS) -c -o $@ $<

clean:
	@echo "clean"
	$(Q)rm -f $(targets) $(objs) $(deps)

.PHONY: all clean