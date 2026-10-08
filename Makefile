PKG_CONFIG ?= pkg-config
FUSE_PKG ?= fuse

ifeq ($(shell command -v $(PKG_CONFIG)), )
$(error You need to install pkg-config in order to compile this sources)
endif

ifeq ($(shell $(PKG_CONFIG) --exists $(FUSE_PKG) && echo yes), )
$(error FUSE 2 development files not found; install macFUSE on macOS or libfuse2 development files on Linux, or set PKG_CONFIG_PATH)
endif

VERSION  = $(shell git describe --tags 2> /dev/null || basename `pwd`)

override CFLAGS  += $(shell $(PKG_CONFIG) $(FUSE_PKG) --cflags) -DFUSE_USE_VERSION=26 -std=gnu99 -g3 -Wall -Wextra
override CFLAGS  += -DEXT4FUSE_VERSION=\"$(VERSION)\"
LDFLAGS += $(shell $(PKG_CONFIG) $(FUSE_PKG) --libs)

ifeq ($(shell uname), Darwin)
MACOSX_DEPLOYMENT_TARGET ?= 15.0
override CFLAGS  += -mmacosx-version-min=$(MACOSX_DEPLOYMENT_TARGET)
LDFLAGS += -mmacosx-version-min=$(MACOSX_DEPLOYMENT_TARGET)

# fuse.pc pulls this flag in for me, but it seems that some old versions don't
override CFLAGS  += -D_FILE_OFFSET_BITS=64
endif

ifeq ($(shell uname), FreeBSD)
override CFLAGS  += -I/usr/local/include -L/usr/local/lib
LDFLAGS += -lexecinfo
endif

BINARY = ext4fuse
SOURCES += fuse-main.o logging.o extents.o disk.o super.o inode.o dcache.o
SOURCES += op_read.o op_readdir.o op_readlink.o op_init.o op_getattr.o op_open.o

$(BINARY): $(SOURCES)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

test-slow: $(BINARY)
	@for T in test/[0-9]*; do ./$$T || exit $$?; done

test: $(BINARY)
	@for T in test/[0-9][0-9][0-9][0-9]-*; do SKIP_SLOW_TESTS=1 ./$$T || exit $$?; done

clean:
	rm -f *.o $(BINARY) test/image-reader
	rm -rf test/logs

.PHONY: test

# Tests the reader against disposable images without mounting or sudo.
test/image-reader: test/image-reader.c $(filter-out fuse-main.o,$(SOURCES))
	$(CC) $(CFLAGS) -I. -o $@ $^ $(LDFLAGS)

test-images: test/image-reader
	./test/image-reader.sh

.PHONY: test-images test-slow clean
