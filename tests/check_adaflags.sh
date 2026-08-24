#!/bin/sh
#
# Process Spawn Manager
#
# Copyright (C) 2026 secunet Security Networks AG
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation; either version 2 of the License, or (at your option)
# any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
# more details.

set -eu

source_root=${1:?source root is required}
source_root=$(CDPATH= cd -- "$source_root" && pwd -P)
test_root=$(mktemp -d "${TMPDIR:-/tmp}/spawn-adaflags.XXXXXX")
trap 'rm -rf "$test_root"' EXIT HUP INT TERM

control_root="$test_root/control/source"
mapped_root="$test_root/mapped/with-a-longer/source/path"

copy_sources()
{
	destination=$1
	mkdir -p "$destination/src" "$destination/tools"
	cp "$source_root/Makefile" \
		"$source_root/spawn_common.gpr" \
		"$source_root/spawn_manager.gpr" \
		"$destination"
	cp "$source_root/tools/spawn_manager.adb" \
		"$source_root/tools/spawn_wrapper.c" \
		"$destination/tools"
	for source in "$source_root"/src/*.adb "$source_root"/src/*.ads; do
		if test "$(basename "$source")" != spawn-version.ads; then
			cp "$source" "$destination/src"
		fi
	done
	printf '%s\n' adaflags-test > "$destination/.version"
}

copy_sources "$control_root"
copy_sources "$mapped_root"

make --no-print-directory -C "$control_root" \
	ADAFLAGS= BUILD_TYPE=debug spawn_manager
make --no-print-directory -C "$mapped_root" \
	ADAFLAGS="-gno-record-gcc-switches -fdebug-prefix-map=$mapped_root=." \
	BUILD_TYPE=debug spawn_manager

control_binary="$control_root/obj/spawn_manager"
mapped_binary="$mapped_root/obj/spawn_manager"
control_strings=$(strings "$control_binary")
mapped_strings=$(strings "$mapped_binary")

if ! printf '%s\n' "$control_strings" \
	| grep -F "$control_root" >/dev/null
then
	echo "control build does not expose its source path" >&2
	exit 1
fi
if printf '%s\n' "$mapped_strings" | grep -F "$mapped_root" >/dev/null; then
	echo "ADAFLAGS did not remove the mapped source path" >&2
	exit 1
fi

sections=$(readelf --wide --sections "$mapped_binary")
printf '%s\n' "$sections" \
	| grep -E '[[:space:]]\.debug_info[[:space:]]' >/dev/null
printf '%s\n' "$sections" \
	| grep -E '[[:space:]]\.debug_line[[:space:]]' >/dev/null

echo "External ADAFLAGS preserve DWARF and normalize source paths"
