VERSION=0.3

DEBUG= -g #-D_DEBUG #-fprofile-arcs -ftest-coverage # -pg -g
CFLAGS+=-O2 -DVERSION=\"${VERSION}\" $(DEBUG)
LDFLAGS+=$(DEBUG)

OBJS=error.o jans.o

all: jans

jans: $(OBJS)
	$(CC) -Wall -W $(OBJS) $(LDFLAGS) -o jans

install: jans
	cp jans /usr/local/sbin

clean:
	rm -f $(OBJS) jans core *.da *.gcov *.bb*

package: clean
	mkdir jans-$(VERSION)
	cp *.c *.h Makefile readme.txt license.txt jans-$(VERSION)
	tar czf jans-$(VERSION).tgz jans-$(VERSION)
	rm -rf jans-$(VERSION)
