# XPath Injection Scanner - Advanced vulnerability detection tool.
# Coded by Chokri Hammedi (blue0x1).
# Licensed under the MIT License.
# Legal use only: use on systems you own or have explicit permission to test.

APP := xpath
VERSION := 1.0.0
ARCH := amd64
PREFIX ?= /usr/local
BINDIR := $(PREFIX)/bin
SRC := src/xpath.nim
BUILD_DIR := build
DIST_DIR := dist
NIMCACHE := $(BUILD_DIR)/nimcache
NIMFLAGS := -d:ssl -d:release --nimcache:$(NIMCACHE)
MINGW_CC ?= x86_64-w64-mingw32-gcc
LINUX_BIN := $(DIST_DIR)/$(APP)-linux-$(ARCH)
WINDOWS_BIN := $(DIST_DIR)/$(APP)-windows-$(ARCH).exe
DEB_ROOT := $(BUILD_DIR)/deb/$(APP)_$(VERSION)_$(ARCH)
DEB_FILE := $(DIST_DIR)/$(APP)_$(VERSION)_$(ARCH).deb

.PHONY: all linux windows install uninstall deb clean

all: linux

$(DIST_DIR):
	mkdir -p $(DIST_DIR)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

linux: $(DIST_DIR) $(BUILD_DIR)
	nim c $(NIMFLAGS) -o:$(LINUX_BIN) $(SRC)

windows: $(DIST_DIR) $(BUILD_DIR)
	@command -v $(MINGW_CC) >/dev/null 2>&1 || { echo "Missing Windows cross compiler: $(MINGW_CC)"; echo "Install mingw-w64 or set MINGW_CC=/path/to/x86_64-w64-mingw32-gcc"; exit 1; }
	nim c $(NIMFLAGS) --os:windows --cpu:amd64 --cc:gcc --gcc.exe:$(MINGW_CC) --gcc.linkerexe:$(MINGW_CC) -o:$(WINDOWS_BIN) $(SRC)

install: linux
	install -Dm755 $(LINUX_BIN) $(DESTDIR)$(BINDIR)/$(APP)

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(APP)

deb: linux
	rm -rf $(DEB_ROOT)
	mkdir -p $(DEB_ROOT)/DEBIAN
	mkdir -p $(DEB_ROOT)/usr/bin
	mkdir -p $(DEB_ROOT)/usr/share/doc/$(APP)
	install -m755 $(LINUX_BIN) $(DEB_ROOT)/usr/bin/$(APP)
	install -m644 README.md $(DEB_ROOT)/usr/share/doc/$(APP)/README.md
	install -m644 LICENSE $(DEB_ROOT)/usr/share/doc/$(APP)/LICENSE
	printf '%s\n' \
		'Package: $(APP)' \
		'Version: $(VERSION)' \
		'Section: utils' \
		'Priority: optional' \
		'Architecture: $(ARCH)' \
		'Maintainer: Chokri Hammedi (blue0x1)' \
		'Description: Advanced XPath injection scanner for authorized security testing' \
		> $(DEB_ROOT)/DEBIAN/control
	dpkg-deb --root-owner-group --build $(DEB_ROOT) $(DEB_FILE)

clean:
	rm -rf $(BUILD_DIR) $(DIST_DIR)
