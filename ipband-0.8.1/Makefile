#
#  ipband - IP bandwidth watchdog
#  Change this variables to match your installation
#
#  Note: When the version changes, you also have to change
#  the RPM spec file

V=0.8.1

MAKE=make

CPPFLAGS=-I/usr/include/pcap
LIBS=-lpcap
CFLAGS := -Wall $(CFLAGS)
CC=gcc 

ifndef PREFIX
PREFIX=/usr
endif

ifndef BINDIR
BINDIR=$(PREFIX)/sbin
endif

ifndef MANDIR
MANDIR=$(PREFIX)/share/man
endif

ifndef MAN8DIR
MAN8DIR=$(MANDIR)/man8
endif

ifndef SYSCONFDIR
#SYSCONFDIR=$(PREFIX)/etc
SYSCONFDIR=/etc
endif

ifndef RCDIR
RCDIR=$(SYSCONFDIR)/rc.d/init.d
endif


BIN 	= ipband
SRC_C 	= main.c error.c init.c packets.c \
	  pcapfunc.c popen.c reports.c utils.c hash.c
OBJ_C   = $(SRC_C:.c=.o)


all: 	$(BIN)

$(BIN):	$(OBJ_C)
	$(CC) -o $(BIN) $(OBJ_C) $(LIBS) $(CFLAGS)
	strip $(BIN)

install-strip:	install

install: all
	mkdir -p $(DESTDIR)$(BINDIR) $(DESTDIR)$(MAN8DIR)
	mkdir -p $(DESTDIR)$(SYSCONFDIR)
	mkdir -p $(DESTDIR)$(RCDIR)
	install -D ipband   		$(DESTDIR)$(BINDIR)/ipband
	install -D ipband.8 		$(DESTDIR)$(MAN8DIR)/ipband.8
	install -D ipband.sample.conf 	$(DESTDIR)$(SYSCONFDIR)/ipband.sample.conf
	install -D ipband.rc 		$(DESTDIR)$(RCDIR)/ipband


clean:
	rm -f *.o
	rm -f ipband


#
#  -------------------------------------------------------------------------
#
#  If we need rpm

SRC_ROOT = Makefile CHANGELOG COPYING README INSTALL ipband.spec styles.css
SRC_SRCS = Makefile *.c *.h ipband.8
SRC_CONF = ipband.sample.conf ipband.rc

tgz:	
	mkdir ipband-$(V)
	cp $(SRC_ROOT) ipband-$(V)/
	cp $(SRC_SRCS) ipband-$(V)/
	cp $(SRC_CONF) ipband-$(V)/
	tar -czvf ipband-$(V).tgz ipband-$(V)/
	rm -rf ipband-$(V)

rpm:    tgz
	mv ipband-$(V).tgz /usr/src/redhat/SOURCES
	cp ipband.spec /usr/src/redhat/SPECS
	rpmbuild -bb ipband.spec
