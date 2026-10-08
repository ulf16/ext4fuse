PKG_CONFIG ?= pkg-config
FUSE_API ?= 3
ifeq ($(filter $(FUSE_API),2 3),)
$(error FUSE_API must be 2 or 3)
endif
FUSE_PKG ?= $(if $(filter 3,$(FUSE_API)),fuse3,fuse)
FUSE_API_VERSION := $(if $(filter 3,$(FUSE_API)),31,26)

ifeq ($(shell command -v $(PKG_CONFIG)), )
$(error You need to install pkg-config in order to compile this sources)
endif

ifeq ($(shell $(PKG_CONFIG) --exists $(FUSE_PKG) && echo yes), )
$(error $(FUSE_PKG) development files not found; install macFUSE on macOS or the matching libfuse development package on Linux, or set PKG_CONFIG_PATH)
endif

ifneq ($(shell $(PKG_CONFIG) --modversion $(FUSE_PKG) | cut -d. -f1),$(FUSE_API))
$(error FUSE_API does not match the major version of $(FUSE_PKG))
endif

VERSION  = $(shell git describe --tags 2> /dev/null || basename `pwd`)

override CFLAGS  += $(shell $(PKG_CONFIG) $(FUSE_PKG) --cflags) -DFUSE_USE_VERSION=$(FUSE_API_VERSION) -D_FILE_OFFSET_BITS=64 -std=gnu99 -g3 -Wall -Wextra
override CFLAGS  += -DEXT4FUSE_VERSION=\"$(VERSION)\"
override LDFLAGS += $(shell $(PKG_CONFIG) $(FUSE_PKG) --libs)

ifeq ($(shell uname), Darwin)
# Use macFUSE's portable stat-based FUSE 3 ABI; no Darwin-specific attributes yet.
ifeq ($(FUSE_API),3)
override CFLAGS += -DFUSE_DARWIN_ENABLE_EXTENSIONS=0
endif
MACOSX_DEPLOYMENT_TARGET ?= 15.0
override CFLAGS  += -mmacosx-version-min=$(MACOSX_DEPLOYMENT_TARGET)
override LDFLAGS += -mmacosx-version-min=$(MACOSX_DEPLOYMENT_TARGET)

endif

ifeq ($(shell uname), FreeBSD)
override CFLAGS  += -I/usr/local/include -L/usr/local/lib
override LDFLAGS += -lexecinfo
endif

BINARY = ext4fuse
SOURCES += fuse-main.o logging.o extents.o disk.o checksum.o super.o inode.o dcache.o
SOURCES += op_read.o op_readdir.o op_readlink.o op_init.o op_getattr.o op_open.o

BUILD_DIR = .build/fuse$(FUSE_API)
OBJECTS = $(addprefix $(BUILD_DIR)/,$(SOURCES))

# Each API has separate objects; always relink the shared output when switching.
$(BINARY): $(OBJECTS) FORCE
	$(CC) $(CFLAGS) -o $@ $(OBJECTS) $(LDFLAGS)

$(BUILD_DIR)/%.o: %.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -MMD -MP -c $< -o $@

-include $(OBJECTS:.o=.d)

FORCE:
.PHONY: FORCE

test-slow: $(BINARY)
	@for T in test/[0-9]*; do ./$$T || exit $$?; done

test: $(BINARY)
	@for T in test/[0-9][0-9][0-9][0-9]-*; do SKIP_SLOW_TESTS=1 ./$$T || exit $$?; done

clean:
	rm -f *.o $(BINARY) test/image-reader test/feature-probe test/corruption-probe
	rm -rf test/logs .build

.PHONY: test

# Tests the reader against disposable images without mounting or sudo.
READER_OBJECTS = $(filter-out $(BUILD_DIR)/fuse-main.o,$(OBJECTS))
test/image-reader: test/image-reader.c $(READER_OBJECTS) FORCE
	$(CC) $(CFLAGS) -I. -o $@ test/image-reader.c $(READER_OBJECTS) $(LDFLAGS)

test-images: test/image-reader
	./test/image-reader.sh

.PHONY: test-images test-slow clean

PYTHON ?= python3
test/feature-probe: test/feature-probe.c $(READER_OBJECTS) FORCE
	$(CC) $(CFLAGS) -I. -o $@ test/feature-probe.c $(READER_OBJECTS) $(LDFLAGS)

test-features: $(BINARY) test/feature-probe
	$(PYTHON) test/features.py

.PHONY: test-features

test/corruption-probe: test/corruption-probe.c $(READER_OBJECTS) FORCE
	$(CC) $(CFLAGS) -I. -o $@ test/corruption-probe.c $(READER_OBJECTS) $(LDFLAGS)

test-corruption: test/corruption-probe
	$(PYTHON) test/corruption.py

.PHONY: test-corruption

test-checksums: test/corruption-probe
	$(PYTHON) test/checksums.py

.PHONY: test-checksums
