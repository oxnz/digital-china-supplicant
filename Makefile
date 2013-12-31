CC	:= clang
FRAMEWORKS	:= -framework Cocoa
LIBRARIES	:= -lobjc
CFLAGS	:= -Wall -Werror
LDFLAGS	:= $(LIBRARIES) $(FRAMEWORKS)

test: test.m
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@
