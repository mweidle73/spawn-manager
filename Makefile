PREFIX ?= $(HOME)/ada

SRCDIR = src
LIBDIR = lib
OBJDIR = obj
COVDIR = $(OBJDIR)/cov

VERSION_SPEC := src/spawn-version.ads
VERSION       = $(shell cat .version | sed 's/^v//')
GIT_REV      := $(shell git describe --always 2> /dev/null)

GPR_FILE = gnat/spawn.gpr

CFLAGS = -W -Wall -Werror -O3

BUILD_TYPE = prod

all: spawn_lib spawn_manager

.version: FORCE
	@if [ -d .git -o -f .git ]; then \
		if [ -r $@ ]; then \
			if [ "$$(cat $@)" != "$(GIT_REV)" ]; then \
				echo $(GIT_REV) > $@; \
			fi; \
		else \
			echo $(GIT_REV) > $@; \
		fi \
	fi

$(VERSION_SPEC): .version
	@echo "package Spawn.Version is"                > $@
	@echo "   Version_String : constant String :=" >> $@
	@echo "     \"$(VERSION)\";"                   >> $@
	@echo "end Spawn.Version;"                     >> $@

spawn_tests:
	@gnatmake -P$@ -p

tests: spawn_tests spawn_manager
	@$(OBJDIR)/spawn_manager 8192 $(OBJDIR)/spawn_manager_0 &
	@$(OBJDIR)/test_runner
	@tests/check_adaflags.sh "$(CURDIR)"

spawn_manager: $(VERSION_SPEC) $(OBJDIR)/spawn_wrapper
	@gnatmake -P$@ -p -XBUILD=$(BUILD_TYPE)

spawn_performance:
	@gnatmake -P$@ -p

spawn_lib:
	@gnatmake -P$@ -p

perf: spawn_performance spawn_manager
	@$(OBJDIR)/perf/performance

$(OBJDIR)/spawn_wrapper: tools/spawn_wrapper.c
	@mkdir -p $(OBJDIR)
	$(CC) -static $(CFLAGS) -o $@ $<

install: install_lib install_manager

install_lib: spawn_lib
	install -d $(PREFIX)/include/spawn
	install -d $(PREFIX)/lib/spawn
	install -d $(PREFIX)/lib/gnat
	install -m 644 $(SRCDIR)/*.ad[bs] $(PREFIX)/include/spawn
	install -m 444 $(LIBDIR)/*.ali $(PREFIX)/lib/spawn
	install -m 444 $(LIBDIR)/libspawn.a $(PREFIX)/lib
	install -m 644 $(GPR_FILE) $(PREFIX)/lib/gnat

install_manager: spawn_manager
	install -m 755 $(OBJDIR)/spawn_manager $(PREFIX)
	install -m 755 $(OBJDIR)/spawn_wrapper $(PREFIX)

cov: spawn_manager
	@rm -f $(COVDIR)/*.gcda
	@gnatmake -Pspawn_tests.gpr -p -XBUILD="coverage"
	@$(OBJDIR)/spawn_manager $(OBJDIR)/spawn_manager_0 &
	@$(COVDIR)/test_runner || true
	@lcov -c -d $(COVDIR) -o $(COVDIR)/cov.info
	@lcov -e $(COVDIR)/cov.info "$(PWD)/src/*.adb" -o $(COVDIR)/cov.info
	@genhtml --no-branch-coverage $(COVDIR)/cov.info -o $(COVDIR)

doc:
	@$(MAKE) -C doc

clean:
	@rm -rf $(OBJDIR)
	@rm -rf $(LIBDIR)
	@$(MAKE) -C doc clean

FORCE:

.PHONY: doc perf tests
