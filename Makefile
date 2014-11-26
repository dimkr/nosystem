CC ?= cc
CFLAGS ?= -O2 -pipe
LDFLAGS ?= -s
DESTDIR ?=
LIB_DIR ?= /lib
MAN_DIR ?= /usr/share/man
DOC_DIR ?= /usr/share/doc

CFLAGS += -Wall -pedantic
LDFLAGS += -shared -Wl,-soname,libsystemd.so.0 -Wl,--version-script=syms.sym
INSTALL = install -v

SRCS = $(wildcard *.c)
OBJECTS = $(SRCS:.c=.o)
HEADERS = $(wildcard *.h)

LIBS = libsystemd.so.0 libsystemd.a

all: $(LIBS)

libsystemd.so.0: $(OBJECTS)
	$(CC) -o $@ $^ $(LDFLAGS)

libsystemd.a: $(OBJECTS)
	ar rcs $@ $^

install: all
	$(INSTALL) -D -m 644 libsystemd.so.0 $(DESTDIR)/$(LIB_DIR)/libsystemd.so.0
	$(INSTALL) -m 644 libsystemd.a $(DESTDIR)/$(LIB_DIR)/libsystemd.a
	$(INSTALL) -D -m 644 README $(DESTDIR)/$(DOC_DIR)/ogg122/README
	$(INSTALL) -m 644 AUTHORS $(DESTDIR)/$(DOC_DIR)/ogg122/AUTHORS
	$(INSTALL) -m 644 UNLICENSE $(DESTDIR)/$(DOC_DIR)/ogg122/UNLICENSE

clean:
	rm -f $(LIBS) $(OBJECTS)
