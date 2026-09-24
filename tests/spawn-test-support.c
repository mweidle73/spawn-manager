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

#include <errno.h>
#include <stddef.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>

#define TEST_PATH_SIZE 4096

static int collide_next_directory;
static char directory_path[TEST_PATH_SIZE];
static int fail_next_chmod;
static int limited_receive_socket = -1;

int __real_chmod(const char *path, mode_t mode);
int __real_mkdir(const char *path, mode_t mode);
ssize_t __real_recv(int socket, void *buffer, size_t length, int flags);

/* Preserve one injected directory path for the Ada ownership assertions. */
static int record_directory_path(const char *path)
{
	size_t length = strlen(path);

	if (length >= sizeof(directory_path)) {
		errno = ENAMETOOLONG;
		return -1;
	}
	memcpy(directory_path, path, length + 1);
	return 0;
}

/* Fail one chmod after mkdir has already transferred directory ownership. */
int __wrap_chmod(const char *path, mode_t mode)
{
	if (!fail_next_chmod)
		return __real_chmod(path, mode);
	fail_next_chmod = 0;
	if (record_directory_path(path) < 0)
		return -1;
	errno = EPERM;
	return -1;
}

/* Create the requested directory but report one synthetic name collision. */
int __wrap_mkdir(const char *path, mode_t mode)
{
	int result;

	if (!collide_next_directory)
		return __real_mkdir(path, mode);
	collide_next_directory = 0;
	if (record_directory_path(path) < 0)
		return -1;
	result = __real_mkdir(path, mode);
	if (result < 0)
		return result;
	errno = EEXIST;
	return -1;
}

/* Limit fixture reads so ready data remains queued after the deadline. */
ssize_t __wrap_recv(int socket, void *buffer, size_t length, int flags)
{
	if (socket == limited_receive_socket && length > 1)
		length = 1;
	return __real_recv(socket, buffer, length, flags);
}

/* Select one fixture socket for one-byte reads, or -1 to disable the limit. */
void spawn_test_limit_receive_chunks(int socket)
{
	limited_receive_socket = socket;
}

/* Return the path created by the synthetic directory-collision fixture. */
const char *spawn_test_directory_path(void)
{
	return directory_path;
}

/* Make the next mkdir leave an empty foreign directory and report EEXIST. */
void spawn_test_collide_next_directory(int enabled)
{
	collide_next_directory = enabled;
	if (enabled)
		directory_path[0] = '\0';
}

/* Make the next chmod fail after recording its already owned directory. */
void spawn_test_fail_next_chmod(int enabled)
{
	fail_next_chmod = enabled;
	if (enabled)
		directory_path[0] = '\0';
}

int spawn_test_directory_mode(const char *path)
{
	struct stat status;

	return stat(path, &status) == 0 ? (int)(status.st_mode & 0777) : -1;
}
