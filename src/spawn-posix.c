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
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define ERROR_FD 3
/* Exit the manager rather than resume after losing containment ownership. */
#define CONTAINMENT_FAILURE_EXIT 125
#define DESCRIPTOR_CEILING_UNINITIALIZED -2
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
 * Cache one descriptor ceiling for the close_range fallback, using procfs when
 * available and the process limit otherwise. Per-request descriptors are
 * created only after fork, so one parent snapshot is enough.
 */
static int descriptor_ceiling = DESCRIPTOR_CEILING_UNINITIALIZED;

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

/* Initialize the complete result record for one terminal outcome. */
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

/* Return CLOCK_MONOTONIC in milliseconds, or -1 when it cannot be read. */
static int64_t monotonic_milliseconds(void)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
		return -1;
	return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

/* Return the highest descriptor permitted by the process soft limit. */
static int limit_descriptor_ceiling(void)
{
	struct rlimit limit;
	rlim_t count;

	if (getrlimit(RLIMIT_NOFILE, &limit) < 0)
		return -1;
	count = limit.rlim_cur;
	if (count == RLIM_INFINITY || count > (rlim_t)INT_MAX) {
		long open_max = sysconf(_SC_OPEN_MAX);

		if (open_max < 0 || open_max > INT_MAX)
			return -1;
		count = (rlim_t)open_max;
	}
	return count > 0 ? (int)(count - 1) : ERROR_FD;
}

/*
 * Convert an absolute monotonic deadline to a poll timeout. A negative
 * deadline remains unlimited, zero means expired, and large values are capped
 * at the interface maximum accepted by poll(2).
 */
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
 * access and allocation. Use the process descriptor limit when procfs is not
 * mounted.
 */
static int highest_open_descriptor(void)
{
	DIR *directory = opendir("/proc/self/fd");
	struct dirent *item;
	int highest = ERROR_FD;
	int scan_fd;

	if (directory == NULL)
		return limit_descriptor_ceiling();
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
		return limit_descriptor_ceiling();
	return highest;
}

/*
 * Report one pre-exec failure without allocation or stdio. fd is a
 * nonblocking error-pipe endpoint and the fixed record is below PIPE_BUF, so
 * the write is atomic whenever it succeeds.
 */
static void report_child_error_to(int fd, int stage, int error_number)
{
	struct child_error error = { stage, error_number };
	ssize_t written;

	do {
		written = write(fd, &error, sizeof(error));
	} while (written < 0 && errno == EINTR);
	_exit(127);
}

/* Report the current errno after the error pipe has been installed at fd 3. */
static void report_child_error(int stage)
{
	report_child_error_to(ERROR_FD, stage, errno);
}

/*
 * Install source as target. When both names already identify the same
 * descriptor, clear FD_CLOEXEC instead of calling dup2(2).
 */
static int duplicate_to(int source, int target)
{
	if (source != target)
		return dup2(source, target);
	return fcntl(source, F_SETFD, 0);
}

/* Open one supported output mode without following the final path symlink. */
static int open_output_file(int mode, const char *path)
{
	if (mode == SPAWN_POSIX_TRUNCATE_FILE)
		return open(path,
			O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC,
			0666);
	errno = EINVAL;
	return -1;
}

/* Block manager termination signals across fork and group publication. */
static int block_manager_signals(sigset_t *original_mask)
{
	sigset_t mask;

	if (sigemptyset(&mask) < 0
	    || sigaddset(&mask, SIGINT) < 0
	    || sigaddset(&mask, SIGTERM) < 0)
		return -1;
	return sigprocmask(SIG_BLOCK, &mask, original_mask);
}

/*
 * Replace the manager's caught dispositions before the child joins its group.
 */
static void reset_signal_handlers(void)
{
	struct sigaction action = { 0 };

	action.sa_handler = SIG_DFL;
	if (sigemptyset(&action.sa_mask) < 0
	    || sigaction(SIGINT, &action, NULL) < 0
	    || sigaction(SIGTERM, &action, NULL) < 0)
		report_child_error(SPAWN_POSIX_RESET_SIGNALS);
}

/* Clear the inherited signal mask after default dispositions are installed. */
static void reset_signal_mask(void)
{
	sigset_t mask;

	if (sigemptyset(&mask) < 0
	    || sigprocmask(SIG_SETMASK, &mask, NULL) < 0)
		report_child_error(SPAWN_POSIX_RESET_SIGNALS);
}

/*
 * Close every descriptor above the dedicated error channel. Prefer the kernel
 * range operation and fall back to a parent-prepared finite descriptor bound;
 * without either mechanism, report a precise pre-exec failure.
 */
static void close_child_descriptors(int highest_descriptor)
{
#ifdef SYS_close_range
	if (syscall(SYS_close_range, 4U, ~0U, 0U) == 0)
		return;
	if (errno != ENOSYS && errno != EINVAL && errno != EPERM)
		report_child_error(SPAWN_POSIX_CLOSE_DESCRIPTORS);
#endif
	if (highest_descriptor < ERROR_FD) {
		errno = ENOSYS;
		report_child_error(SPAWN_POSIX_CLOSE_DESCRIPTORS);
	}
	if (highest_descriptor == ERROR_FD)
		return;
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

	/* Normalize the private pre-exec error channel to the fixed descriptor. */
	(void)close(error_read_fd);
	if (error_write_fd != ERROR_FD) {
		if (dup2(error_write_fd, ERROR_FD) < 0) {
			int saved_errno = errno;

			/*
			 * ERROR_FD still belongs to the inherited manager state. Report
			 * through the known pipe endpoint instead of writing to fd 3.
			 */
			report_child_error_to(error_write_fd,
				SPAWN_POSIX_CREATE_ERROR_PIPE, saved_errno);
		}
		(void)close(error_write_fd);
	}

	/*
	 * Establish safe signal state and couple the direct leader to this manager.
	 * Forked target descendants need external cgroup containment if the manager
	 * dies through an uncatchable event and cannot clean the process group.
	 */
	reset_signal_handlers();
	if (setpgid(0, 0) < 0)
		report_child_error(SPAWN_POSIX_PROCESS_GROUP);
	if (prctl(PR_SET_NO_NEW_PRIVS, 1L, 0L, 0L, 0L) < 0)
		report_child_error(SPAWN_POSIX_PARENT_DEATH);
	if (prctl(PR_SET_PDEATHSIG, SIGKILL) < 0)
		report_child_error(SPAWN_POSIX_PARENT_DEATH);
	if (getppid() != expected_parent) {
		errno = ESRCH;
		report_child_error(SPAWN_POSIX_PARENT_DEATH);
	}
	reset_signal_mask();

	/* Install the version-1 stdin, stdout and stderr contract. */
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

	/* Apply remaining process-local state, close private fds and exec once. */
	if (directory[0] != '\0' && chdir(directory) < 0)
		report_child_error(SPAWN_POSIX_CHANGE_DIRECTORY);
	close_child_descriptors(highest_descriptor);
	if (fcntl(ERROR_FD, F_SETFD, FD_CLOEXEC) < 0)
		report_child_error(SPAWN_POSIX_CLOSE_DESCRIPTORS);

	execve(executable, argv, inherit_environment ? environ : envp);
	report_child_error(SPAWN_POSIX_EXEC);
}

/*
 * Read one fixed child-error record. Return 1 for a complete record, 0 for
 * pipe EOF, 2 when a nonblocking retry is needed and -1 for any invalid read.
 */
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

/* Open a Linux pidfd for deadline waits, or return -1 with syscall errno. */
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

/*
 * Observe request-leader exit without reaping it. Retaining the zombie pins
 * the numeric process-group identity until every group signal has been sent.
 * Return 1 after observation, 0 at the deadline and -1 on a wait error.
 */
static int observe_leader(
	pid_t pid,
	int pidfd,
	int64_t deadline,
	siginfo_t *information)
{
	for (;;) {
		siginfo_t observed = { 0 };
		int options = WEXITED | WNOWAIT;
		int waited;

		if (deadline >= 0)
			options |= WNOHANG;
		do {
			waited = waitid(P_PID, (id_t)pid, &observed, options);
		} while (waited < 0 && errno == EINTR);
		if (waited < 0)
			return -1;
		if (observed.si_pid == pid) {
			*information = observed;
			return 1;
		}
		if (deadline < 0) {
			errno = ECHILD;
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

/*
 * Reap an already observed leader and retire its published group identity as
 * one signal-atomic transition. Failure leaves the identity published unless
 * waitpid proved the leader was collected, so the caller can fail-stop safely.
 */
static int reap_observed_leader(pid_t pid, int *status)
{
	sigset_t original_mask;
	pid_t waited;
	int wait_error;

	if (block_manager_signals(&original_mask) < 0)
		return -1;
	do {
		waited = waitpid(pid, status, 0);
	} while (waited < 0 && errno == EINTR);
	wait_error = waited < 0 ? errno : ECHILD;
	if (waited == pid)
		active_group = 0;
	if (sigprocmask(SIG_SETMASK, &original_mask, NULL) < 0)
		return -1;
	if (waited != pid) {
		errno = wait_error;
		return -1;
	}
	return 0;
}

/* Reap adopted group members until none remain or the deadline fails. */
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
 * Terminate one request group while its unreaped leader pins the numeric group
 * identity. Optional grace is reserved for timeout and error cleanup; normal
 * post-exit cleanup sends both signals immediately. Stop publishing the group
 * before reaping can make its number reusable. A setsid descendant is outside
 * this contract and requires the separate cgroup policy.
 */
static int terminate_group(pid_t pid, int *leader_status, int allow_grace)
{
	int64_t deadline;

	if (kill(-pid, SIGTERM) < 0 && errno != ESRCH)
		return -1;
	deadline = monotonic_milliseconds() + TERMINATION_GRACE_MS;
	while (allow_grace && remaining_milliseconds(deadline) > 0) {
		struct timespec pause = {
			0, POLL_SLICE_MS * 1000 * 1000
		};
		(void)nanosleep(&pause, NULL);
	}
	if (kill(-pid, SIGKILL) < 0 && errno != ESRCH)
		return -1;
	active_group = 0;
	{
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

/*
 * Async-signal-safe manager hook: kill the active request group and preserve
 * the interrupted code's errno. Normal execution still owns all reaping.
 */
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
	int containment_failed = 0;
	int manager_signals_blocked = 0;
	int group_setup_error = 0;
	int64_t started;
	int64_t deadline;
	pid_t pid;
	pid_t parent_pid = getpid();
	struct child_error child_error = { 0, 0 };
	siginfo_t leader_information = { 0 };
	sigset_t original_signal_mask;

	/*
	 * Phase 1: prepare manager-side supervision before a child exists. The
	 * subreaper, error channel and fallback descriptor ceiling are shared by
	 * every later phase but never become request policy.
	 */
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
	if (descriptor_ceiling == DESCRIPTOR_CEILING_UNINITIALIZED) {
		descriptor_ceiling = highest_open_descriptor();
	}
	highest_descriptor = descriptor_ceiling;
	if (block_manager_signals(&original_signal_mask) < 0) {
		set_result(result, SPAWN_POSIX_INTERNAL_ERROR, -1, 0,
			SPAWN_POSIX_RESET_SIGNALS, errno);
		(void)close(error_pipe[0]);
		(void)close(error_pipe[1]);
		return -1;
	}
	manager_signals_blocked = 1;

	/*
	 * Phase 2: fork exactly once, then establish the request process group in
	 * both participants so scheduling cannot leave the child uncontained.
	 */
	pid = fork();
	if (pid == 0)
		child_exec(parent_pid, error_pipe[0], error_pipe[1], executable,
			argv, inherit_environment, envp, directory, stdout_mode,
			stdout_path, stderr_mode, stderr_path, highest_descriptor);
	if (pid < 0) {
		int fork_errno = errno;

		if (sigprocmask(SIG_SETMASK, &original_signal_mask, NULL) < 0) {
			set_result(result, SPAWN_POSIX_INTERNAL_ERROR, -1, 0,
				SPAWN_POSIX_RESET_SIGNALS, errno);
			(void)close(error_pipe[0]);
			(void)close(error_pipe[1]);
			return -1;
		}
		set_result(result, SPAWN_POSIX_SPAWN_FAILED, -1, 0,
			SPAWN_POSIX_FORK, fork_errno);
		(void)close(error_pipe[0]);
		(void)close(error_pipe[1]);
		return 0;
	}
	(void)close(error_pipe[1]);
	active_group = (sig_atomic_t)pid;
	if (setpgid(pid, pid) < 0 && errno != EACCES && errno != ESRCH)
		group_setup_error = errno;
	if (sigprocmask(SIG_SETMASK, &original_signal_mask, NULL) < 0) {
		set_result(result, SPAWN_POSIX_INTERNAL_ERROR, -1, 0,
			SPAWN_POSIX_RESET_SIGNALS, errno);
		goto cleanup;
	}
	manager_signals_blocked = 0;
	if (group_setup_error != 0) {
		set_result(result, SPAWN_POSIX_INTERNAL_ERROR, -1, 0,
			SPAWN_POSIX_PROCESS_GROUP, group_setup_error);
		goto cleanup;
	}

	/*
	 * Phase 3: prepare efficient leader waiting and one overflow-safe monotonic
	 * deadline. Unlimited requests deliberately skip pidfd deadline handling.
	 */
	if (timeout_ms >= 0) {
		pidfd = open_pidfd(pid);
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

	/*
	 * Phase 4: cross the exec barrier. EOF means FD_CLOEXEC observed a successful
	 * exec, a record is a precise pre-exec failure, and zero is the child timeout.
	 */
	switch (wait_for_exec(error_pipe[0], deadline, &child_error)) {
	case 2:
		{
			siginfo_t ignored = { 0 };

			if (observe_leader(pid, pidfd, -1, &ignored) < 0) {
				set_result(result, SPAWN_POSIX_INTERNAL_ERROR, -1, 0,
					SPAWN_POSIX_WAIT, errno);
				goto cleanup;
			}
			if (reap_observed_leader(pid, &status) < 0) {
				set_result(result, SPAWN_POSIX_INTERNAL_ERROR, -1, 0,
					SPAWN_POSIX_WAIT, errno);
				containment_failed = 1;
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
		if (terminate_group(pid, &status, 1) < 0) {
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

	/* Phase 5: wait for the executed leader or turn its deadline into timeout. */
	if (!leader_reaped) {
		int waited = observe_leader(
			pid, pidfd, deadline, &leader_information);
		if (waited == 0) {
			if (terminate_group(pid, &status, 1) < 0) {
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
	}

	/*
	 * A fast child may exit before the exec barrier was drained completely.
	 * Consume a late fixed error record before trusting its wait status.
	 */
	{
		int exec_state = read_child_error(error_pipe[0], &child_error);
		if (exec_state == 1) {
			if (reap_observed_leader(pid, &status) < 0) {
				set_result(result, SPAWN_POSIX_INTERNAL_ERROR, -1, 0,
					SPAWN_POSIX_WAIT, errno);
				containment_failed = 1;
				goto cleanup;
			}
			leader_reaped = 1;
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

	/* Translate observed status only while the leader still pins its group id. */
	if (leader_information.si_code == CLD_EXITED)
		set_result(result, SPAWN_POSIX_EXITED,
			leader_information.si_status, 0,
			SPAWN_POSIX_NO_FAILURE, 0);
	else if (leader_information.si_code == CLD_KILLED
	    || leader_information.si_code == CLD_DUMPED)
		set_result(result, SPAWN_POSIX_SIGNALED, -1,
			leader_information.si_status,
			SPAWN_POSIX_NO_FAILURE, 0);
	else
		set_result(result, SPAWN_POSIX_INTERNAL_ERROR, -1, 0,
			SPAWN_POSIX_WAIT, EPROTO);

	/*
	 * Phase 6: a terminal leader may leave descendants in its group. Terminate
	 * and reap them before allowing that leader result to cross the boundary.
	 */
	if (terminate_group(pid, &status, 0) < 0) {
		set_result(result, SPAWN_POSIX_INTERNAL_ERROR, -1, 0,
			SPAWN_POSIX_TERMINATE_GROUP, errno);
		containment_failed = 1;
	} else
		leader_reaped = 1;

cleanup:
	/* Close parent descriptors and contain failures through one ownership exit. */
	if (result->kind == SPAWN_POSIX_INTERNAL_ERROR && !containment_failed
	    && !leader_reaped && terminate_group(pid, &status, 1) < 0) {
		set_result(result, SPAWN_POSIX_INTERNAL_ERROR, -1, 0,
			SPAWN_POSIX_TERMINATE_GROUP, errno);
		containment_failed = 1;
	}
	if (containment_failed) {
		/* Never resume the manager after losing request-group ownership. */
		spawn_posix_terminate_current();
		_exit(CONTAINMENT_FAILURE_EXIT);
	}
	if (manager_signals_blocked
	    && sigprocmask(SIG_SETMASK, &original_signal_mask, NULL) < 0)
		_exit(CONTAINMENT_FAILURE_EXIT);
	active_group = 0;
	if (pidfd >= 0)
		(void)close(pidfd);
	(void)close(error_pipe[0]);
	return result->kind == SPAWN_POSIX_INTERNAL_ERROR ? -1 : 0;
}
