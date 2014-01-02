CC	:= clang
CPP	:= clang++
FRAMEWORKS	:= 
LIBRARIES	:= -lcurl
CFLAGS	:= -Wall -Werror
LDFLAGS	:= $(LIBRARIES) $(FRAMEWORKS)

test: test.c
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@
