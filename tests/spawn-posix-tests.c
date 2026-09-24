/*
 * Process Spawn Manager
 *
 * Copyright (C) 2026 secunet Security Networks AG
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 */

#define _GNU_SOURCE

#include "spawn-posix.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define SPECIAL_ARGUMENT "space\tquote'\"\\glob*?[$(not-shell)]"
#define CONTAINMENT_EXIT_STATUS 125

static unsigned int passed;
/* Test-only linker wrappers inject one precise supervision failure each. */
static pid_t wrapper_owner = -1;
static int fail_group_termination_once;
static int fail_parent_setpgid_once;
static int fail_proc_scan_once;
static int interrupt_waitpid_once;
static const char *group_setup_wait_path;

DIR *__real_opendir(const char *path);
int __real_kill(pid_t pid, int signal);
int __real_setpgid(pid_t pid, pid_t group);
pid_t __real_waitpid(pid_t pid, int *status, int options);

/* Fail the first parent-side SIGTERM sent to a request process group. */
int __wrap_kill(pid_t pid, int signal)
{
	if (getpid() == wrapper_owner && pid < 0 && signal == SIGTERM
	    && fail_group_termination_once) {
		fail_group_termination_once = 0;
		errno = EPERM;
		return -1;
	}
	return __real_kill(pid, signal);
}

/* Hide /proc/self/fd once so close_range must carry descriptor cleanup. */
DIR *__wrap_opendir(const char *path)
{
	if (getpid() == wrapper_owner && fail_proc_scan_once
	    && strcmp(path, "/proc/self/fd") == 0) {
		fail_proc_scan_once = 0;
		errno = ENOENT;
		return NULL;
	}
	return __real_opendir(path);
}

/* Fail the first parent-side attempt to establish the request group. */
int __wrap_setpgid(pid_t pid, pid_t group)
{
	if (getpid() == wrapper_owner && pid > 0
	    && fail_parent_setpgid_once) {
		if (group_setup_wait_path != NULL) {
			for (int attempt = 0; attempt < 100; ++attempt) {
				struct stat status;
				struct timespec pause = { 0, 10 * 1000 * 1000 };

				if (stat(group_setup_wait_path, &status) == 0
				    && status.st_size > 0)
					break;
				(void)nanosleep(&pause, NULL);
			}
		}
		fail_parent_setpgid_once = 0;
		errno = EPERM;
		return -1;
	}
	return __real_setpgid(pid, group);
}

/* Interrupt the first blocking parent wait selected by one regression. */
pid_t __wrap_waitpid(pid_t pid, int *status, int options)
{
	if (getpid() == wrapper_owner && pid > 0 && options == 0
	    && interrupt_waitpid_once) {
		interrupt_waitpid_once = 0;
		errno = EINTR;
		return -1;
	}
	return __real_waitpid(pid, status, options);
}

static void fail(const char *message)
{
	fprintf(stderr, "FAIL POSIX core: %s\n", message);
	exit(1);
}

static void pass(const char *message)
{
	++passed;
	printf("PASS POSIX core: %s\n", message);
}

static void require(int condition, const char *message)
{
	if (!condition)
		fail(message);
}

static char *read_file(const char *path)
{
	struct stat status;
	char *content;
	FILE *file;
	size_t count;

	require(stat(path, &status) == 0, "stat output");
	content = malloc((size_t)status.st_size + 1);
	require(content != NULL, "allocate output");
	file = fopen(path, "r");
	require(file != NULL, "open output");
	count = fread(content, 1, (size_t)status.st_size, file);
	require(count == (size_t)status.st_size, "read output");
	require(fclose(file) == 0, "close output");
	content[count] = '\0';
	return content;
}

static void require_exited(
	const struct spawn_posix_result *result,
	int status,
	const char *message)
{
	require(result->kind == SPAWN_POSIX_EXITED, message);
	require(result->exit_status == status, message);
}

static double monotonic_seconds(void)
{
	struct timespec now;

	require(clock_gettime(CLOCK_MONOTONIC, &now) == 0, "read monotonic clock");
	return (double)now.tv_sec + (double)now.tv_nsec / 1000000000.0;
}

static int compare_samples(const void *left, const void *right)
{
	double lhs = *(const double *)left;
	double rhs = *(const double *)right;

	return lhs < rhs ? -1 : lhs > rhs;
}

static int benchmark(void)
{
	enum { sample_count = 1000 };
	char *empty_environment[] = { NULL };
	char *arguments[] = { "/bin/true", NULL };
	struct spawn_posix_result result;
	double samples[sample_count];
	double total = 0.0;

	for (size_t index = 0; index < sample_count; ++index) {
		double started = monotonic_seconds();
		require(spawn_posix_execute(
			"/bin/true", arguments, 0, empty_environment, "/", 0, NULL,
			0, NULL, -1, &result) == 0, "benchmark execute");
		require_exited(&result, 0, "benchmark result");
		samples[index] = monotonic_seconds() - started;
		total += samples[index];
	}
	qsort(samples, sample_count, sizeof(samples[0]), compare_samples);
	printf("* POSIX direct /bin/true mean=% .9f median=% .9f p95=% .9f\n",
		total / sample_count, samples[sample_count / 2],
		samples[(sample_count * 95 + 99) / 100 - 1]);
	return 0;
}

static int fixture_verify(int argc, char *argv[], char *envp[])
{
	char cwd[PATH_MAX];
	char expected_cwd[PATH_MAX + 16];

	if (argc != 5 || argv[3][0] != '\0'
	    || strcmp(argv[4], SPECIAL_ARGUMENT) != 0)
		return 81;
	if (envp[0] == NULL || envp[1] == NULL || envp[2] != NULL
	    || strcmp(envp[0], "ONLY=visible value") != 0
	    || strncmp(envp[1], "EXPECTED_CWD=", 13) != 0)
		return 82;
	if (getcwd(cwd, sizeof(cwd)) == NULL)
		return 83;
	if (snprintf(expected_cwd, sizeof(expected_cwd), "EXPECTED_CWD=%s", cwd)
	    >= (int)sizeof(expected_cwd)
	    || strcmp(envp[1], expected_cwd) != 0)
		return 84;
	if (write(STDOUT_FILENO, "verified stdout\n", 16) != 16
	    || write(STDERR_FILENO, "verified stderr\n", 16) != 16)
		return 85;
	return 0;
}

static int fixture_tree(void)
{
	pid_t descendant = fork();

	if (descendant < 0)
		return 86;
	if (descendant == 0) {
		for (;;)
			pause();
	}
	printf("%ld\n", (long)descendant);
	fflush(stdout);
	for (;;)
		pause();
}

static int fixture_orphan(void)
{
	pid_t descendant = fork();

	if (descendant < 0)
		return 95;
	if (descendant == 0) {
		for (;;)
			pause();
	}
	printf("%ld\n", (long)descendant);
	fflush(stdout);
	return 0;
}

static int write_repeated(int descriptor, size_t count, char value)
{
	char buffer[4096];

	memset(buffer, value, sizeof(buffer));
	while (count > 0) {
		size_t chunk = count < sizeof(buffer) ? count : sizeof(buffer);
		ssize_t written;

		do {
			written = write(descriptor, buffer, chunk);
		} while (written < 0 && errno == EINTR);
		if (written <= 0)
			return -1;
		count -= (size_t)written;
	}
	return 0;
}

static int fixture_output(int argc, char *argv[])
{
	char *end;
	unsigned long count;

	if (argc != 4)
		return 91;
	errno = 0;
	count = strtoul(argv[3], &end, 10);
	if (errno != 0 || *end != '\0' || count > 1024 * 1024)
		return 92;
	if (write_repeated(STDOUT_FILENO, count, 'o') < 0)
		return 93;
	if (write_repeated(STDERR_FILENO, count, 'e') < 0)
		return 94;
	return 0;
}

static int fixture(int argc, char *argv[], char *envp[])
{
	if (argc < 3)
		return 80;
	if (strcmp(argv[2], "verify") == 0)
		return fixture_verify(argc, argv, envp);
	if (strcmp(argv[2], "exit37") == 0)
		return 37;
	if (strcmp(argv[2], "signal") == 0) {
		raise(SIGTERM);
		return 87;
	}
	if (strcmp(argv[2], "stdin") == 0) {
		char byte;
		return read(STDIN_FILENO, &byte, 1) == 0 ? 0 : 88;
	}
	if (strcmp(argv[2], "parent") == 0) {
		printf("%ld\n", (long)getppid());
		return 0;
	}
	if (strcmp(argv[2], "fd") == 0 && argc == 4) {
		int fd = atoi(argv[3]);
		return fcntl(fd, F_GETFD) < 0 && errno == EBADF ? 0 : 89;
	}
	if (strcmp(argv[2], "output") == 0)
		return fixture_output(argc, argv);
	if (strcmp(argv[2], "tree") == 0)
		return fixture_tree();
	if (strcmp(argv[2], "orphan") == 0)
		return fixture_orphan();
	return 90;
}

static void test_exit_and_signal(const char *self)
{
	char *empty_environment[] = { NULL };
	char *exit_arguments[] = { (char *)self, "fixture", "exit37", NULL };
	char *signal_arguments[] = { (char *)self, "fixture", "signal", NULL };
	struct spawn_posix_result result;

	require(spawn_posix_execute(
		self, exit_arguments, 0, empty_environment, "/", 0, NULL, 0,
		NULL, 1000, &result) == 0, "execute exit fixture");
	require_exited(&result, 37, "exact exit status");
	require(spawn_posix_execute(
		self, signal_arguments, 0, empty_environment, "/", 0, NULL, 0,
		NULL, 1000, &result) == 0, "execute signal fixture");
	require(result.kind == SPAWN_POSIX_SIGNALED
		&& result.signal_number == SIGTERM, "exact signal");
	require(spawn_posix_execute(
		self, exit_arguments, 0, empty_environment, "/", 0, NULL, 0,
		NULL, INT64_MAX, &result) == 0, "execute maximum-timeout fixture");
	require_exited(&result, 37, "maximum timeout result");
	pass("exact exit and signal results");
}

static void test_error_pipe_duplication(const char *self)
{
	char *empty_environment[] = { NULL };
	char *arguments[] = { (char *)self, "fixture", "exit37", NULL };
	struct spawn_posix_result result;
	struct rlimit original_limit;
	struct rlimit limited_limit;
	int saved_stdin;
	int saved_stdout;
	int call_result;
	int restore_limit_result;
	int restore_stdin_result;
	int restore_stdout_result;

	require(spawn_posix_execute(
		self, arguments, 0, empty_environment, "/", 0, NULL, 0, NULL,
		1000, &result) == 0, "prepare descriptor ceiling");
	require_exited(&result, 37, "descriptor-ceiling preparation result");

	/*
	 * The preparation call caches the parent's descriptor ceiling. Free
	 * descriptors zero and one, then restrict new descriptors to 0..2 so
	 * pipe2 returns them and the child's dup2(error_write_fd, 3) fails with
	 * EBADF. The original implementation then lost the error record and
	 * reported exit 127; the dedicated pipe endpoint must preserve the
	 * structured failure.
	 */
	require(getrlimit(RLIMIT_NOFILE, &original_limit) == 0,
		"read descriptor limit");
	require(original_limit.rlim_cur >= 3, "descriptor limit supports fixture");
	saved_stdin = dup(STDIN_FILENO);
	saved_stdout = dup(STDOUT_FILENO);
	require(saved_stdin >= 0 && saved_stdout >= 0,
		"save standard descriptors");
	limited_limit = original_limit;
	limited_limit.rlim_cur = 3;
	require(setrlimit(RLIMIT_NOFILE, &limited_limit) == 0,
		"restrict descriptor limit");
	require(close(STDIN_FILENO) == 0 && close(STDOUT_FILENO) == 0,
		"free low descriptors");

	call_result = spawn_posix_execute(
		self, arguments, 0, empty_environment, "/", 0, NULL, 0, NULL,
		1000, &result);

	restore_limit_result = setrlimit(RLIMIT_NOFILE, &original_limit);
	restore_stdin_result = dup2(saved_stdin, STDIN_FILENO);
	restore_stdout_result = dup2(saved_stdout, STDOUT_FILENO);
	(void)close(saved_stdin);
	(void)close(saved_stdout);
	require(restore_limit_result == 0 && restore_stdin_result == STDIN_FILENO
		&& restore_stdout_result == STDOUT_FILENO,
		"restore descriptor environment");
	require(call_result == 0
		&& result.kind == SPAWN_POSIX_SPAWN_FAILED
		&& result.failure_stage == SPAWN_POSIX_CREATE_ERROR_PIPE
		&& result.error_number == EBADF,
		"report error-pipe duplication failure");
	pass("error-pipe duplication failure channel");
}

static void test_exec_failure(const char *self)
{
	char *empty_environment[] = { NULL };
	char *arguments[] = { (char *)self, NULL };
	struct spawn_posix_result result;

	require(spawn_posix_execute(
		"/definitely/missing/spawn-target", arguments, 0,
		empty_environment, "/", 0, NULL, 0, NULL, 1000, &result) == 0,
		"execute missing target");
	require(result.kind == SPAWN_POSIX_SPAWN_FAILED
		&& result.failure_stage == SPAWN_POSIX_EXEC
		&& result.error_number == ENOENT, "classify missing target");
	pass("pre-exec failure stage and errno");
}

static void test_request_data(
	const char *self,
	const char *directory,
	const char *stdout_path,
	const char *stderr_path)
{
	char expected_cwd[PATH_MAX + 16];
	char *environment[] = { "ONLY=visible value", expected_cwd, NULL };
	char *arguments[] = {
		(char *)self, "fixture", "verify", "", SPECIAL_ARGUMENT, NULL
	};
	struct spawn_posix_result result;
	struct stat stdout_status;
	struct stat stderr_status;
	char *stdout_content;
	char *stderr_content;

	require(snprintf(
		expected_cwd, sizeof(expected_cwd), "EXPECTED_CWD=%s", directory)
		< (int)sizeof(expected_cwd), "construct expected cwd");
	require(spawn_posix_execute(
		self, arguments, 0, environment, directory,
		SPAWN_POSIX_TRUNCATE_FILE, stdout_path,
		SPAWN_POSIX_TRUNCATE_FILE, stderr_path, 1000, &result) == 0,
		"execute request-data fixture");
	require_exited(&result, 0, "request-data result");
	require(stat(stdout_path, &stdout_status) == 0
		&& stat(stderr_path, &stderr_status) == 0,
		"stat split streams");
	require((stdout_status.st_mode & 0777) == 0644
		&& (stderr_status.st_mode & 0777) == 0644,
		"umask-filtered stream create modes");
	stdout_content = read_file(stdout_path);
	stderr_content = read_file(stderr_path);
	require(strcmp(stdout_content, "verified stdout\n") == 0,
		"independent stdout");
	require(strcmp(stderr_content, "verified stderr\n") == 0,
		"independent stderr");
	free(stdout_content);
	free(stderr_content);
	require(chmod(stdout_path, 0600) == 0
		&& chmod(stderr_path, 0640) == 0,
		"prepare existing stream modes");
	require(spawn_posix_execute(
		self, arguments, 0, environment, directory,
		SPAWN_POSIX_TRUNCATE_FILE, stdout_path,
		SPAWN_POSIX_TRUNCATE_FILE, stderr_path, 1000, &result) == 0,
		"truncate existing stream fixtures");
	require_exited(&result, 0, "existing-stream result");
	require(stat(stdout_path, &stdout_status) == 0
		&& stat(stderr_path, &stderr_status) == 0,
		"restat existing streams");
	require((stdout_status.st_mode & 0777) == 0600
		&& (stderr_status.st_mode & 0777) == 0640,
		"preserve existing stream modes");
	pass("argv, replacement environment, cwd and split streams");
}

static void test_stdin_and_descriptors(
	const char *self,
	int inherited_fd)
{
	char fd_text[32];
	char *empty_environment[] = { NULL };
	char *stdin_arguments[] = { (char *)self, "fixture", "stdin", NULL };
	char *fd_arguments[] = {
		(char *)self, "fixture", "fd", fd_text, NULL
	};
	struct spawn_posix_result result;

	require(spawn_posix_execute(
		self, stdin_arguments, 0, empty_environment, "/", 0, NULL, 0,
		NULL, 1000, &result) == 0, "execute stdin fixture");
	require_exited(&result, 0, "stdin is /dev/null");
	require(snprintf(fd_text, sizeof(fd_text), "%d", inherited_fd)
		< (int)sizeof(fd_text), "format descriptor");
	fd_arguments[3] = fd_text;
	require(spawn_posix_execute(
		self, fd_arguments, 0, empty_environment, "/", 0, NULL, 0,
		NULL, 1000, &result) == 0, "execute descriptor fixture");
	require_exited(&result, 0, "undeclared descriptor closed");
	pass("/dev/null stdin and descriptor closure");
}

static void test_stream_nofollow(
	const char *self,
	const char *symlink_path)
{
	char *empty_environment[] = { NULL };
	char *arguments[] = { (char *)self, "fixture", "exit37", NULL };
	struct spawn_posix_result result;

	require(symlink("/dev/null", symlink_path) == 0, "create stream symlink");
	require(spawn_posix_execute(
		self, arguments, 0, empty_environment, "/",
		SPAWN_POSIX_TRUNCATE_FILE, symlink_path, 0, NULL, 1000,
		&result) == 0, "execute nofollow fixture");
	require(result.kind == SPAWN_POSIX_SPAWN_FAILED
		&& result.failure_stage == SPAWN_POSIX_OPEN_STDOUT
		&& result.error_number == ELOOP, "reject stream symlink");
	require(unlink(symlink_path) == 0, "remove stream symlink");
	pass("nofollow stream failure");
}

static void test_interrupted_group_setup_reap(void)
{
	char *empty_environment[] = { NULL };
	char *arguments[] = { "/bin/true", NULL };
	struct spawn_posix_result result;
	int status;
	pid_t waited;

	wrapper_owner = getpid();
	fail_parent_setpgid_once = 1;
	interrupt_waitpid_once = 1;
	require(spawn_posix_execute(
		"/bin/true", arguments, 0, empty_environment, "/", 0, NULL,
		0, NULL, -1, &result) < 0, "classify group setup failure");
	wrapper_owner = -1;
	require(result.kind == SPAWN_POSIX_INTERNAL_ERROR
		&& result.failure_stage == SPAWN_POSIX_PROCESS_GROUP,
		"report group setup failure");
	errno = 0;
	waited = __real_waitpid(-1, &status, WNOHANG);
	require(waited < 0 && errno == ECHILD,
		"interrupted group setup left an unreaped child");
	pass("EINTR preserves group setup reap ownership");
}

static void test_no_proc_descriptor_cleanup(void)
{
	char *empty_environment[] = { NULL };
	char *arguments[] = { "/bin/true", NULL };
	struct spawn_posix_result result;

	wrapper_owner = getpid();
	fail_proc_scan_once = 1;
	require(spawn_posix_execute(
		"/bin/true", arguments, 0, empty_environment, "/", 0, NULL,
		0, NULL, -1, &result) == 0, "execute without proc descriptor scan");
	wrapper_owner = -1;
	require_exited(&result, 0, "close_range without proc descriptor scan");
	pass("descriptor cleanup without procfs");
}

static void test_group_setup_failure_descendants(
	const char *self,
	const char *pid_path)
{
	char *empty_environment[] = { NULL };
	char *arguments[] = { (char *)self, "fixture", "orphan", NULL };
	struct spawn_posix_result result;
	char *pid_content;
	pid_t descendant;
	pid_t waited;
	int descendant_status = 0;
	int wait_errno;

	wrapper_owner = getpid();
	group_setup_wait_path = pid_path;
	fail_parent_setpgid_once = 1;
	require(spawn_posix_execute(
		self, arguments, 0, empty_environment, "/",
		SPAWN_POSIX_TRUNCATE_FILE, pid_path, 0, NULL, -1,
		&result) < 0, "classify group setup descendant failure");
	group_setup_wait_path = NULL;
	wrapper_owner = -1;
	require(result.kind == SPAWN_POSIX_INTERNAL_ERROR
		&& result.failure_stage == SPAWN_POSIX_PROCESS_GROUP,
		"report group setup descendant failure");
	pid_content = read_file(pid_path);
	descendant = (pid_t)strtol(pid_content, NULL, 10);
	free(pid_content);
	require(descendant > 0, "read group setup descendant pid");
	errno = 0;
	waited = __real_waitpid(descendant, &descendant_status, WNOHANG);
	wait_errno = errno;
	if (waited == 0) {
		(void)__real_kill(descendant, SIGKILL);
		(void)__real_waitpid(descendant, &descendant_status, 0);
	}
	require(waited < 0 && wait_errno == ECHILD,
		"group setup failure left a descendant behind");
	pass("group setup failure contains descendants");
}

/* Prove an uncontained group makes its owning manager process fail-stop. */
static void test_termination_failure_fail_stop(
	const char *self,
	const char *pid_path)
{
	pid_t supervisor;
	pid_t descendant;
	pid_t waited;
	int descendant_status = 0;
	int supervisor_status = 0;
	char *pid_content;

	require(prctl(PR_SET_CHILD_SUBREAPER, 1) == 0,
		"enable test subreaper");
	supervisor = fork();
	require(supervisor >= 0, "fork containment supervisor");
	if (supervisor == 0) {
		char *empty_environment[] = { NULL };
		char *arguments[] = { (char *)self, "fixture", "orphan", NULL };
		struct spawn_posix_result result;

		wrapper_owner = getpid();
		fail_group_termination_once = 1;
		(void)spawn_posix_execute(
			self, arguments, 0, empty_environment, "/",
			SPAWN_POSIX_TRUNCATE_FILE, pid_path, 0, NULL, 1000,
			&result);
		_exit(96);
	}
	require(__real_waitpid(supervisor, &supervisor_status, 0) == supervisor,
		"wait for containment supervisor");
	pid_content = read_file(pid_path);
	descendant = (pid_t)strtol(pid_content, NULL, 10);
	free(pid_content);
	require(descendant > 0, "read fail-stop descendant pid");
	for (int attempt = 0; attempt < 100; ++attempt) {
		waited = __real_waitpid(descendant, &descendant_status, WNOHANG);
		if (waited != 0)
			break;
		struct timespec pause = { 0, 10 * 1000 * 1000 };
		(void)nanosleep(&pause, NULL);
	}
	if (waited == 0) {
		(void)__real_kill(descendant, SIGKILL);
		(void)__real_waitpid(descendant, &descendant_status, 0);
	}
	require(WIFEXITED(supervisor_status)
		&& WEXITSTATUS(supervisor_status) ==
			CONTAINMENT_EXIT_STATUS,
		"termination failure did not fail-stop supervisor");
	require(waited == descendant && WIFSIGNALED(descendant_status)
		&& WTERMSIG(descendant_status) == SIGKILL,
		"fail-stop did not kill the uncontained group");
	pass("termination failure fail-stops group owner");
}

static void test_timeout_group(
	const char *self,
	const char *pid_path)
{
	char *empty_environment[] = { NULL };
	char *arguments[] = { (char *)self, "fixture", "tree", NULL };
	struct spawn_posix_result result;
	char *pid_content;
	pid_t descendant;

	require(spawn_posix_execute(
		self, arguments, 0, empty_environment, "/",
		SPAWN_POSIX_TRUNCATE_FILE, pid_path, 0, NULL, 500, &result) == 0,
		"execute timeout fixture");
	require(result.kind == SPAWN_POSIX_TIMED_OUT, "classify timeout");
	pid_content = read_file(pid_path);
	descendant = (pid_t)strtol(pid_content, NULL, 10);
	free(pid_content);
	require(descendant > 0, "read descendant pid");
	require(kill(descendant, 0) < 0 && errno == ESRCH,
		"timeout descendant survived");
	pass("timeout kills and reaps request group");
}

static void test_success_group_cleanup(
	const char *self,
	const char *pid_path)
{
	char *empty_environment[] = { NULL };
	char *arguments[] = { (char *)self, "fixture", "orphan", NULL };
	struct spawn_posix_result result;
	char *pid_content;
	pid_t descendant;

	require(spawn_posix_execute(
		self, arguments, 0, empty_environment, "/",
		SPAWN_POSIX_TRUNCATE_FILE, pid_path, 0, NULL, 1000, &result) == 0,
		"execute successful orphan fixture");
	require_exited(&result, 0, "preserve successful leader result");
	pid_content = read_file(pid_path);
	descendant = (pid_t)strtol(pid_content, NULL, 10);
	free(pid_content);
	require(descendant > 0, "read successful descendant pid");
	require(kill(descendant, 0) < 0 && errno == ESRCH,
		"successful descendant survived");
	pass("success kills and reaps remaining request group");
}

int main(int argc, char *argv[], char *envp[])
{
	char self[PATH_MAX];
	char cwd[PATH_MAX];
	char root[PATH_MAX];
	char stdout_path[PATH_MAX];
	char stderr_path[PATH_MAX];
	char symlink_path[PATH_MAX];
	char pid_path[PATH_MAX];
	int source_fd;
	int inherited_fd;
	mode_t original_umask;

	if (argc == 2 && strcmp(argv[1], "--benchmark") == 0)
		return benchmark();
	if (argc > 1 && strcmp(argv[1], "fixture") == 0)
		return fixture(argc, argv, envp);
	original_umask = umask(0022);
	require(realpath(argv[0], self) != NULL, "resolve test executable");
	require(getcwd(cwd, sizeof(cwd)) != NULL, "get test cwd");
	require(snprintf(root, sizeof(root), "%s/obj/posix-core-test", cwd)
		< (int)sizeof(root), "construct test root");
	require(mkdir(root, 0700) == 0 || errno == EEXIST, "create test root");
	require(snprintf(stdout_path, sizeof(stdout_path), "%s/stdout", root)
		< (int)sizeof(stdout_path), "construct stdout path");
	require(snprintf(stderr_path, sizeof(stderr_path), "%s/stderr", root)
		< (int)sizeof(stderr_path), "construct stderr path");
	require(snprintf(symlink_path, sizeof(symlink_path), "%s/link", root)
		< (int)sizeof(symlink_path), "construct symlink path");
	require(snprintf(pid_path, sizeof(pid_path), "%s/pid", root)
		< (int)sizeof(pid_path), "construct pid path");
	(void)unlink(stdout_path);
	(void)unlink(stderr_path);
	(void)unlink(symlink_path);
	(void)unlink(pid_path);

	/*
	 * Model manager and GNU Make jobserver descriptors: all persistent
	 * descriptors exist before the first request and remain open in the
	 * manager while every target must close them.
	 */
	source_fd = open("/dev/null", O_RDONLY);
	require(source_fd >= 0, "open descriptor fixture");
	inherited_fd = fcntl(source_fd, F_DUPFD, 100);
	require(inherited_fd >= 100, "duplicate descriptor fixture");

	test_no_proc_descriptor_cleanup();
	test_exit_and_signal(self);
	test_error_pipe_duplication(self);
	test_exec_failure(self);
	test_termination_failure_fail_stop(self, pid_path);
	require(unlink(pid_path) == 0, "reset fail-stop pid file");
	test_interrupted_group_setup_reap();
	test_group_setup_failure_descendants(self, pid_path);
	require(unlink(pid_path) == 0, "reset group setup descendant pid file");
	test_request_data(self, root, stdout_path, stderr_path);
	test_stdin_and_descriptors(self, inherited_fd);
	test_stream_nofollow(self, symlink_path);
	test_timeout_group(self, pid_path);
	require(unlink(pid_path) == 0, "reset descendant pid file");
	test_success_group_cleanup(self, pid_path);

	require(close(inherited_fd) == 0 && close(source_fd) == 0,
		"close descriptor fixture");
	require(unlink(stdout_path) == 0, "remove stdout");
	require(unlink(stderr_path) == 0, "remove stderr");
	require(unlink(pid_path) == 0, "remove pid file");
	require(rmdir(root) == 0, "remove test root");
	(void)umask(original_umask);
	printf("PASS POSIX core total: %u\n", passed);
	return 0;
}
