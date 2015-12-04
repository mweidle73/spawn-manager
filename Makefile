PREFIX ?= $(HOME)/ada

SRCDIR = src
LIBDIR = lib
OBJDIR = obj
COVDIR = $(OBJDIR)/cov

GPR_FILE = gnat/spawn.gpr

CFLAGS = -W -Wall -Werror -O3

BUILD_TYPE = prod

all: spawn_lib spawn_manager

spawn_tests:
	@gnatmake -P$@ -p

tests: spawn_tests spawn_manager
	@$(OBJDIR)/spawn_manager $(OBJDIR)/spawn_manager_0 &
	@$(OBJDIR)/test_runner

spawn_manager: $(OBJDIR)/spawn_wrapper
	@gnatmake -P$@ -p -XBUILD=$(BUILD_TYPE)

spawn_manager_debug: $(OBJDIR)/spawn_wrapper
	@gnatmake -Pspawn_manager -p -XBUILD="debug"

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

cov:
	@rm -f $(COVDIR)/*.gcda
	@gnatmake -Pspawn_tests.gpr -p -XBUILD="coverage" -XBIT=$(BIT)
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

.PHONY: clean cov doc install install_lib install_manager perf spawn_lib \
	spawn_performance spawn_manager spawn_manager_debug spawn_tests tests
