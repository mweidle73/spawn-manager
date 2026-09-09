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
 *
 * As a special exception, if other files instantiate generics from this unit,
 * or you link this unit with other files to produce an executable, this unit
 * does not by itself cause the resulting executable to be covered by the GNU
 * General Public License. This exception does not invalidate any other reason
 * why the executable might be covered by the GNU Public License.
 */

#define _GNU_SOURCE

#include "spawn-posix.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define ERROR_FD 3
#define POLL_SLICE_MS 10
#define TERMINATION_GRACE_MS 100

/*
 * ERROR_FD is the sole descriptor intentionally kept across child setup. The
 * close sweep starts at four, then FD_CLOEXEC closes this error channel only
 * after execve has successfully replaced the child image.
 */

extern char **environ;

/*
 * The manager is single-threaded and executes one request at a time. The
 * signal handler only reads this process-group id and calls kill(2), so
 * sig_atomic_t is sufficient and no policy state crosses the C boundary.
 */
static volatile sig_atomic_t active_group;

/*
 * The manager opens every persistent descriptor before its request loop.
 * Cache that first complete ceiling for the close_range fallback; per-request
 * descriptors are created only after fork. The normal close_range path still
 * closes the complete live range independently of this value.
 */
static int descriptor_ceiling = -1;

/*
 * Subreaper mode makes orphaned in-group descendants waitable by this manager,
 * so termination can reap the complete request group instead of only its
 * leader. It is process-wide and therefore enabled once in this single-
 * threaded manager.
 */
static int subreaper_enabled;

struct child_error {
	int stage;
	int error_number;
};

static void set_result(
	struct spawn_posix_result *result,
	int kind,
	int exit_status,
	int signal_number,
	int failure_stage,
	int error_number)
{
	result->kind = kind;
	result->exit_status = exit_status;
	result->signal_number = signal_number;
	result->failure_stage = failure_stage;
	result->error_number = error_number;
}

static int64_t monotonic_milliseconds(void)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
		return -1;
	return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

static int remaining_milliseconds(int64_t deadline)
{
	int64_t now;
	int64_t remaining;

	if (deadline < 0)
		return -1;
	now = monotonic_milliseconds();
	if (now < 0 || now >= deadline)
		return 0;
	remaining = deadline - now;
	return remaining > INT_MAX ? INT_MAX : (int)remaining;
}

/*
 * Snapshot the finite descriptor range in the parent. This keeps the
 * post-fork fallback used when close_range(2) is unavailable free of directory
 * access and allocation. The manager is single-threaded, and every persistent
 * descriptor exists before the first request, so later requests cannot raise
 * this ceiling in the parent.
 */
static int highest_open_descriptor(void)
{
	DIR *directory = opendir("/proc/self/fd");
	struct dirent *item;
	int highest = ERROR_FD;
	int scan_fd;

	if (directory == NULL)
		return -1;
	scan_fd = dirfd(directory);
	while ((item = readdir(directory)) != NULL) {
		char *end;
		long value;

		errno = 0;
		value = strtol(item->d_name, &end, 10);
		if (errno == 0 && *end == '\0' && value >= 0 && value <= INT_MAX
		    && value != scan_fd && value > highest)
			highest = (int)value;
	}
	if (closedir(directory) < 0)
		return -1;
	return highest;
}

/*
 * Report one pre-exec failure without allocation or stdio. ERROR_FD is a
 * nonblocking pipe and the fixed record is below PIPE_BUF, so the write is
 * atomic whenever it succeeds.
 */
static void report_child_error(int stage)
{
	struct child_error error = { stage, errno };
	ssize_t written;

	do {
		written = write(ERROR_FD, &error, sizeof(error));
	} while (written < 0 && errno == EINTR);
	_exit(127);
}

static int duplicate_to(int source, int target)
{
	if (source != target)
		return dup2(source, target);
	return fcntl(source, F_SETFD, 0);
}

static int open_output_file(int mode, const char *path)
{
	if (mode == SPAWN_POSIX_TRUNCATE_FILE)
		return open(path,
			O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC,
			0600);
	errno = EINVAL;
	return -1;
}

static void reset_signal_mask(void)
{
	sigset_t mask;

	if (sigemptyset(&mask) < 0
	    || sigprocmask(SIG_SETMASK, &mask, NULL) < 0)
		report_child_error(SPAWN_POSIX_RESET_SIGNALS);
}

static void close_child_descriptors(int highest_descriptor)
{
#ifdef SYS_close_range
	if (syscall(SYS_close_range, 4U, ~0U, 0U) == 0)
		return;
	if (errno != ENOSYS && errno != EINVAL && errno != EPERM)
		report_child_error(SPAWN_POSIX_CLOSE_DESCRIPTORS);
#endif
	for (int fd = ERROR_FD + 1; fd <= highest_descriptor; ++fd)
		(void)close(fd);
}

/*
 * This is the complete post-fork child path. argv, envp, paths and the
 * descriptor bound were prepared by the parent. The child performs only
 * bounded memory operations and direct OS setup; it neither allocates nor
 * enters the Ada runtime.
 */
static void child_exec(
	pid_t expected_parent,
	int error_read_fd,
	int error_write_fd,
	const char *executable,
	char *const argv[],
	int inherit_environment,
	char *const envp[],
	const char *directory,
	int stdout_mode,
	const char *stdout_path,
	int stderr_mode,
	const char *stderr_path,
	int highest_descriptor)
{
	int null_fd;
	int output_fd;

	(void)close(error_read_fd);
	if (error_write_fd != ERROR_FD) {
		if (dup2(error_write_fd, ERROR_FD) < 0)
			report_child_error(SPAWN_POSIX_CREATE_ERROR_PIPE);
		(void)close(error_write_fd);
	}
	if (setpgid(0, 0) < 0)
		report_child_error(SPAWN_POSIX_PROCESS_GROUP);
	if (prctl(PR_SET_PDEATHSIG, SIGKILL) < 0)
		report_child_error(SPAWN_POSIX_PARENT_DEATH);
	if (getppid() != expected_parent) {
		errno = ESRCH;
		report_child_error(SPAWN_POSIX_PARENT_DEATH);
	}

	null_fd = open("/dev/null", O_RDWR | O_CLOEXEC);
	if (null_fd < 0)
		report_child_error(SPAWN_POSIX_OPEN_STDIN);
	if (duplicate_to(null_fd, STDIN_FILENO) < 0)
		report_child_error(SPAWN_POSIX_DUP_STDIN);

	output_fd = stdout_mode == SPAWN_POSIX_NULL_STREAM
		? null_fd : open_output_file(stdout_mode, stdout_path);
	if (output_fd < 0)
		report_child_error(SPAWN_POSIX_OPEN_STDOUT);
	if (duplicate_to(output_fd, STDOUT_FILENO) < 0)
		report_child_error(SPAWN_POSIX_DUP_STDOUT);
	if (output_fd != null_fd && output_fd != STDOUT_FILENO)
		(void)close(output_fd);

	output_fd = stderr_mode == SPAWN_POSIX_NULL_STREAM
		? null_fd : open_output_file(stderr_mode, stderr_path);
	if (output_fd < 0)
		report_child_error(SPAWN_POSIX_OPEN_STDERR);
	if (duplicate_to(output_fd, STDERR_FILENO) < 0)
		report_child_error(SPAWN_POSIX_DUP_STDERR);
	if (output_fd != null_fd && output_fd != STDERR_FILENO)
		(void)close(output_fd);
	if (null_fd > STDERR_FILENO)
		(void)close(null_fd);

	if (directory[0] != '\0' && chdir(directory) < 0)
		report_child_error(SPAWN_POSIX_CHANGE_DIRECTORY);
	reset_signal_mask();
	close_child_descriptors(highest_descriptor);
	if (fcntl(ERROR_FD, F_SETFD, FD_CLOEXEC) < 0)
		report_child_error(SPAWN_POSIX_CLOSE_DESCRIPTORS);

	execve(executable, argv, inherit_environment ? environ : envp);
	report_child_error(SPAWN_POSIX_EXEC);
}

static int read_child_error(int fd, struct child_error *error)
{
	ssize_t count;

	do {
		count = read(fd, error, sizeof(*error));
	} while (count < 0 && errno == EINTR);
	if (count == (ssize_t)sizeof(*error))
		return 1;
	if (count == 0)
		return 0;
	if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
		return 2;
	errno = EPROTO;
	return -1;
}

static int open_pidfd(pid_t pid)
{
#ifdef SYS_pidfd_open
	return (int)syscall(SYS_pidfd_open, pid, 0U);
#else
	(void)pid;
	errno = ENOSYS;
	return -1;
#endif
}

/*
 * Wait for either successful exec (pipe EOF), a pre-exec error record or the
 * request deadline. The pipe closes on both exec and child exit, so this phase
 * does not need to reap or otherwise race the later waitpid owner.
 */
static int wait_for_exec(
	int error_fd,
	int64_t deadline,
	struct child_error *child_error)
{
	for (;;) {
		struct pollfd item = { error_fd, POLLIN | POLLHUP, 0 };
		int rc;

		rc = poll(&item, 1, remaining_milliseconds(deadline));
		if (rc < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (rc == 0)
			return 0;
		if ((item.revents & (POLLIN | POLLHUP)) != 0) {
			int state = read_child_error(error_fd, child_error);
			if (state != 2)
				return state < 0 ? -1 : state + 1;
		}
	}
}

static int wait_for_leader(pid_t pid, int pidfd, int64_t deadline, int *status)
{
	if (deadline < 0) {
		pid_t waited;
		do {
			waited = waitpid(pid, status, 0);
		} while (waited < 0 && errno == EINTR);
		return waited == pid ? 1 : -1;
	}

	for (;;) {
		pid_t waited = waitpid(pid, status, WNOHANG);
		if (waited == pid)
			return 1;
		if (waited < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (remaining_milliseconds(deadline) == 0)
			return 0;
		if (pidfd >= 0) {
			struct pollfd item = { pidfd, POLLIN, 0 };
			int rc = poll(&item, 1, remaining_milliseconds(deadline));
			if (rc < 0 && errno != EINTR)
				return -1;
			if (rc == 0)
				return 0;
		} else {
			struct timespec pause = {
				0, POLL_SLICE_MS * 1000 * 1000
			};
			(void)nanosleep(&pause, NULL);
		}
	}
}

static int process_group_exists(pid_t group)
{
	if (kill(-group, 0) == 0)
		return 1;
	return errno == EPERM;
}

static int reap_group(pid_t group, int64_t deadline)
{
	struct timespec pause = { 0, POLL_SLICE_MS * 1000 * 1000 };

	for (;;) {
		int status;
		pid_t waited = waitpid(-group, &status, WNOHANG);
		if (waited > 0)
			continue;
		if (waited < 0 && errno == ECHILD)
			return 0;
		if (waited < 0 && errno != EINTR)
			return -1;
		if (remaining_milliseconds(deadline) == 0) {
			errno = ETIMEDOUT;
			return -1;
		}
		(void)nanosleep(&pause, NULL);
	}
}

/*
 * A timeout is terminal only after the leader and all children which remained
 * in its request group have been killed and reaped. A setsid descendant is
 * outside this contract and requires the separately pending cgroup decision.
 */
static int terminate_group(
	pid_t pid,
	int pidfd,
	int *leader_status,
	int leader_reaped)
{
	int64_t deadline;

	if (kill(-pid, SIGTERM) < 0 && errno != ESRCH)
		return -1;
	deadline = monotonic_milliseconds() + TERMINATION_GRACE_MS;
	if (!leader_reaped) {
		int waited = wait_for_leader(pid, pidfd, deadline, leader_status);
		if (waited < 0) {
			if (errno != ECHILD)
				return -1;
			leader_reaped = 1;
		} else if (waited > 0) {
			leader_reaped = 1;
		}
	}
	while (process_group_exists(pid)
	    && remaining_milliseconds(deadline) > 0) {
		struct timespec pause = {
			0, POLL_SLICE_MS * 1000 * 1000
		};
		(void)nanosleep(&pause, NULL);
	}
	if (process_group_exists(pid)
	    && kill(-pid, SIGKILL) < 0 && errno != ESRCH)
		return -1;
	if (!leader_reaped) {
		pid_t waited;
		do {
			waited = waitpid(pid, leader_status, 0);
		} while (waited < 0 && errno == EINTR);
		if (waited < 0 && errno != ECHILD)
			return -1;
	}
	return reap_group(
		pid, monotonic_milliseconds() + TERMINATION_GRACE_MS);
}

void spawn_posix_terminate_current(void)
{
	int saved_errno = errno;
	sig_atomic_t group = active_group;

	if (group > 0)
		(void)kill(-(pid_t)group, SIGKILL);
	errno = saved_errno;
}

/*
 * The parent side owns one linear lifecycle:
 *
 *   prepare error channel -> fork -> confirm exec -> wait for leader
 *       -> terminate remaining group members -> close all local descriptors
 *
 * Every exit after a successful fork reaches cleanup. A normal result returns
 * zero; -1 means the result record describes an internal supervision failure.
 * Expected exec failures and child termination results still return zero.
 */
int spawn_posix_execute(
	const char *executable,
	char *const argv[],
	int inherit_environment,
	char *const envp[],
	const char *directory,
	int stdout_mode,
	const char *stdout_path,
	int stderr_mode,
	const char *stderr_path,
	int64_t timeout_ms,
	struct spawn_posix_result *result)
{
	int error_pipe[2];
	int highest_descriptor;
	int pidfd = -1;
	int status = 0;
	int leader_reaped = 0;
	int64_t started;
	int64_t deadline;
	pid_t pid;
	pid_t parent_pid = getpid();
	struct child_error child_error = { 0, 0 };

	set_result(result, SPAWN_POSIX_INTERNAL_ERROR, -1, 0,
		SPAWN_POSIX_NO_FAILURE, 0);
	if (!subreaper_enabled) {
		if (prctl(PR_SET_CHILD_SUBREAPER, 1) < 0) {
			set_result(result, SPAWN_POSIX_INTERNAL_ERROR, -1, 0,
				SPAWN_POSIX_ENABLE_SUBREAPER, errno);
			return -1;
		}
		subreaper_enabled = 1;
	}
	if (pipe2(error_pipe, O_CLOEXEC | O_NONBLOCK) < 0) {
		set_result(result, SPAWN_POSIX_INTERNAL_ERROR, -1, 0,
			SPAWN_POSIX_CREATE_ERROR_PIPE, errno);
		return -1;
	}
	if (descriptor_ceiling < 0) {
		descriptor_ceiling = highest_open_descriptor();
		if (descriptor_ceiling < 0) {
			set_result(result, SPAWN_POSIX_INTERNAL_ERROR, -1, 0,
				SPAWN_POSIX_CREATE_ERROR_PIPE, errno);
			(void)close(error_pipe[0]);
			(void)close(error_pipe[1]);
			return -1;
		}
	}
	highest_descriptor = descriptor_ceiling;

	pid = fork();
	if (pid == 0)
		child_exec(parent_pid, error_pipe[0], error_pipe[1], executable,
			argv, inherit_environment, envp, directory, stdout_mode,
			stdout_path, stderr_mode, stderr_path, highest_descriptor);
	if (pid < 0) {
		set_result(result, SPAWN_POSIX_SPAWN_FAILED, -1, 0,
			SPAWN_POSIX_FORK, errno);
		(void)close(error_pipe[0]);
		(void)close(error_pipe[1]);
		return 0;
	}
	(void)close(error_pipe[1]);
	active_group = (sig_atomic_t)pid;
	if (setpgid(pid, pid) < 0 && errno != EACCES && errno != ESRCH) {
		int saved_errno = errno;
		(void)kill(pid, SIGKILL);
		(void)waitpid(pid, &status, 0);
		leader_reaped = 1;
		set_result(result, SPAWN_POSIX_INTERNAL_ERROR, -1, 0,
			SPAWN_POSIX_PROCESS_GROUP, saved_errno);
		goto cleanup;
	}
	if (timeout_ms >= 0) {
		pidfd = open_pidfd(pid);
		if (pidfd < 0 && errno != ENOSYS && errno != EINVAL) {
			set_result(result, SPAWN_POSIX_INTERNAL_ERROR, -1, 0,
				SPAWN_POSIX_WAIT, errno);
			goto cleanup;
		}
	}
	started = monotonic_milliseconds();
	if (started < 0) {
		set_result(result, SPAWN_POSIX_INTERNAL_ERROR, -1, 0,
			SPAWN_POSIX_WAIT, errno);
		goto cleanup;
	}
	deadline = timeout_ms < 0 ? -1
		: timeout_ms > INT64_MAX - started ? INT64_MAX
		: started + timeout_ms;

	switch (wait_for_exec(error_pipe[0], deadline, &child_error)) {
	case 2:
		{
			pid_t waited;
			do {
				waited = waitpid(pid, &status, 0);
			} while (waited < 0 && errno == EINTR);
			if (waited < 0) {
				set_result(result, SPAWN_POSIX_INTERNAL_ERROR, -1, 0,
					SPAWN_POSIX_WAIT, errno);
				goto cleanup;
			}
		}
		leader_reaped = 1;
		set_result(result, SPAWN_POSIX_SPAWN_FAILED, -1, 0,
			child_error.stage, child_error.error_number);
		goto cleanup;
	case 1:
		break;
	case 0:
		if (terminate_group(pid, pidfd, &status, leader_reaped) < 0) {
			set_result(result, SPAWN_POSIX_INTERNAL_ERROR, -1, 0,
				SPAWN_POSIX_TERMINATE_GROUP, errno);
			goto cleanup;
		}
		leader_reaped = 1;
		set_result(result, SPAWN_POSIX_TIMED_OUT, -1, 0,
			SPAWN_POSIX_NO_FAILURE, 0);
		goto cleanup;
	default:
		set_result(result, SPAWN_POSIX_INTERNAL_ERROR, -1, 0,
			SPAWN_POSIX_WAIT, errno);
		goto cleanup;
	}

	if (!leader_reaped) {
		int waited = wait_for_leader(pid, pidfd, deadline, &status);
		if (waited == 0) {
			if (terminate_group(pid, pidfd, &status, 0) < 0) {
				set_result(result, SPAWN_POSIX_INTERNAL_ERROR, -1, 0,
					SPAWN_POSIX_TERMINATE_GROUP, errno);
				goto cleanup;
			}
			leader_reaped = 1;
			set_result(result, SPAWN_POSIX_TIMED_OUT, -1, 0,
				SPAWN_POSIX_NO_FAILURE, 0);
			goto cleanup;
		}
		if (waited < 0) {
			set_result(result, SPAWN_POSIX_INTERNAL_ERROR, -1, 0,
				SPAWN_POSIX_WAIT, errno);
			goto cleanup;
		}
		leader_reaped = 1;
	}

	{
		int exec_state = read_child_error(error_pipe[0], &child_error);
		if (exec_state == 1) {
			set_result(result, SPAWN_POSIX_SPAWN_FAILED, -1, 0,
				child_error.stage, child_error.error_number);
			goto cleanup;
		}
		if (exec_state < 0 || exec_state == 2) {
			set_result(result, SPAWN_POSIX_INTERNAL_ERROR, -1, 0,
				SPAWN_POSIX_WAIT, EPROTO);
			goto cleanup;
		}
	}

	if (WIFEXITED(status))
		set_result(result, SPAWN_POSIX_EXITED, WEXITSTATUS(status), 0,
			SPAWN_POSIX_NO_FAILURE, 0);
	else if (WIFSIGNALED(status))
		set_result(result, SPAWN_POSIX_SIGNALED, -1, WTERMSIG(status),
			SPAWN_POSIX_NO_FAILURE, 0);
	else
		set_result(result, SPAWN_POSIX_INTERNAL_ERROR, -1, 0,
			SPAWN_POSIX_WAIT, EPROTO);

	if (process_group_exists(pid)
	    && terminate_group(pid, pidfd, &status, 1) < 0)
		set_result(result, SPAWN_POSIX_INTERNAL_ERROR, -1, 0,
			SPAWN_POSIX_TERMINATE_GROUP, errno);

cleanup:
	if (result->kind == SPAWN_POSIX_INTERNAL_ERROR && !leader_reaped)
		(void)terminate_group(pid, pidfd, &status, 0);
	active_group = 0;
	if (pidfd >= 0)
		(void)close(pidfd);
	(void)close(error_pipe[0]);
	return result->kind == SPAWN_POSIX_INTERNAL_ERROR ? -1 : 0;
}
