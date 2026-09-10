/*
 * Process Spawn Manager
 *
 * Copyright (C) 2026 secunet Security Networks AG
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static void fail(const char *operation)
{
	perror(operation);
	exit(1);
}

static void read_exact(int fd, unsigned char *data, size_t length)
{
	while (length > 0) {
		ssize_t count = read(fd, data, length);

		if (count < 0 && errno == EINTR)
			continue;
		if (count <= 0)
			fail("read request");
		data += count;
		length -= (size_t)count;
	}
}

static void write_exact(int fd, const unsigned char *data, size_t length)
{
	while (length > 0) {
		ssize_t count = write(fd, data, length);

		if (count < 0 && errno == EINTR)
			continue;
		if (count <= 0)
			fail("write result");
		data += count;
		length -= (size_t)count;
	}
}

static uint32_t decode_u32(const unsigned char *data)
{
	return (uint32_t)data[0] << 24 | (uint32_t)data[1] << 16
		| (uint32_t)data[2] << 8 | data[3];
}

int main(int argc, char *argv[])
{
	static const unsigned char result[] = {
		'S', 'P', 'W', 'N', 0, 1, 0, 3, 0, 0, 0, 9,
		5, 0, 0, 0, 4, 's', 't', 'o', 'p'
	};
	unsigned char header[12];
	unsigned char *payload;
	struct sockaddr_un address = { .sun_family = AF_UNIX };
	uint32_t payload_length;
	int listener;
	int connection;

	if (argc != 3)
		return 2;
	if (strlen(argv[2]) >= sizeof(address.sun_path))
		return 3;
	strcpy(address.sun_path, argv[2]);

	listener = socket(AF_UNIX, SOCK_STREAM, 0);
	if (listener < 0)
		fail("socket");
	if (bind(listener, (struct sockaddr *)&address, sizeof(address)) < 0)
		fail("bind");
	if (listen(listener, 1) < 0)
		fail("listen");
	connection = accept(listener, NULL, NULL);
	if (connection < 0)
		fail("accept");

	read_exact(connection, header, sizeof(header));
	payload_length = decode_u32(header + 8);
	payload = malloc(payload_length == 0 ? 1 : payload_length);
	if (payload == NULL)
		fail("malloc");
	read_exact(connection, payload, payload_length);
	free(payload);

	write_exact(connection, result, sizeof(result));
	if (close(connection) < 0 || close(listener) < 0)
		fail("close");
	return 0;
}
