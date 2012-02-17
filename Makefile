PREFIX ?= $(HOME)/ada

SRCDIR = src
LIBDIR = lib
OBJDIR = obj
COVDIR = $(OBJDIR)/cov

GPR_FILE = gnat/spawn.gpr

all: spawn_lib spawn_manager

spawn_tests:
	@gnatmake -P$@ -p

tests: spawn_tests spawn_manager_debug
	@$(OBJDIR)/test_runner

spawn_manager:
	@gnatmake -P$@ -p

spawn_manager_debug:
	@gnatmake -Pspawn_manager -p -XBUILD="debug"

spawn_performance:
	@gnatmake -P$@ -p

spawn_lib:
	@gnatmake -P$@ -p

perf: spawn_performance spawn_manager
	@$(OBJDIR)/perf/performance

install: install_lib install_manager

install_lib: spawn_lib
	install -d $(PREFIX)/include/spawn
	install -d $(PREFIX)/lib/spawn
	install -d $(PREFIX)/lib/gnat
	install -m 644 $(SRCDIR)/*.ad[bs] $(PREFIX)/include/spawn
	install -m 444 $(LIBDIR)/*.ali $(PREFIX)/lib/spawn
	install -m 444 $(LIBDIR)/libspawn.a $(PREFIX)/lib/spawn
	install -m 644 $(GPR_FILE) $(PREFIX)/lib/gnat

install_manager: spawn_manager
	install -m 755 $(OBJDIR)/spawn_manager $(PREFIX)

cov:
	@rm -f $(COVDIR)/*.gcda
	@gnatmake -Pspawn_tests.gpr -p -XBUILD="coverage" -XBIT=$(BIT)
	@$(COVDIR)/test_runner || true
	@lcov -c -d $(COVDIR) -o $(COVDIR)/cov.info
	@lcov -e $(COVDIR)/cov.info "$(PWD)/src/*.adb" -o $(COVDIR)/cov.info
	@genhtml --no-branch-coverage $(COVDIR)/cov.info -o $(COVDIR)

clean:
	@rm -rf $(OBJDIR)
	@rm -rf $(LIBDIR)

PHONY: clean cov build install install_lib install_manager perf spawn_lib \
	spawn_performance spawn_manager spawn_manager_debug spawn_tests tests
