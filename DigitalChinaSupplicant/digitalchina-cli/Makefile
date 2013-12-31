CC	:= gcc
CFLAGS	:= -Wall -O2 -Wno-deprecated-declarations
LDFLAGS	:= -lcrypto -lpcap
VERSION	:= 1.12
OS	:= ${shell uname -s}
ifeq ($(OS), Darwin)
	LDFLAGS	+= -liconv
	CC	:= clang
endif
all: dcclient dcclient.1
dcclient: main.o dcclient.o
	$(CC) $(LDFLAGS) $^ -o $@

dcclient.o: dcclient.h

dcclient.1: dcclient
	help2man -n DigitalChinaSupplicant -s 1 ./dcclient -o $@

%.o:%.c
	$(CC) $(CFLAGS) -c -o $@ $<
install:
	./install
clean:
	rm -f *.o
	rm -f .DS_Store
tarball: dcclient
	make && make clean
	tar -zcvf dcclient-$(VERSION).tar.gz	\
		--exclude .git	\
		--exclude .DS_Store	\
		--exclude dcclient-$(VERSION).tar.gz	\
		.
deb: dcclient
	mkdir -p dcclient-$(VERSION)/usr/local/bin
	cp dcclient dcclient/usr/local/bin
	mv DEBIAN dcclient/DEBIAN
	dpkg-deb -b dcclient
push:
	make clean
	git add *
	git commit
	git push
.PHONY: install clean deb tarball push
