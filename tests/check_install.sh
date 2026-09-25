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
test_root=$(mktemp -d "${TMPDIR:-/tmp}/spawn-install.XXXXXX")
trap 'rm -rf "$test_root"' EXIT HUP INT TERM

prefix=$test_root/prefix
mkdir -p "$prefix"

# A replacement install must also remove a wrapper left by an older bundle.
: > "$prefix/spawn_wrapper"

make --no-print-directory -C "$source_root" PREFIX="$prefix" install

test -x "$prefix/spawn_manager"
test ! -e "$prefix/spawn_wrapper"
test -f "$prefix/lib/libspawn.a"
test -f "$prefix/lib/gnat/spawn.gpr"
test -f "$prefix/include/spawn/spawn-pool.ads"
test ! -e "$prefix/include/spawn/spawn-signals.ads"

echo "Install contains the manager and removes the retired wrapper"
