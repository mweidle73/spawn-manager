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

#include <stddef.h>
#include <sys/socket.h>
#include <sys/stat.h>

static int limited_receive_socket = -1;

ssize_t __real_recv(int socket, void *buffer, size_t length, int flags);

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

int spawn_test_directory_mode(const char *path)
{
	struct stat status;

	return stat(path, &status) == 0 ? (int)(status.st_mode & 0777) : -1;
}
