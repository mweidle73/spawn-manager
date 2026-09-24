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
signals_body=$source_root/tools/spawn-signals.adb
signals_spec=$source_root/tools/spawn-signals.ads
manager_body=$source_root/tools/spawn_manager.adb

# The attached handler cannot recover from an exception. Contain the active
# group first, keep fallible socket cleanup in one best-effort block and then
# exit without any further operation which can raise.
actual=$(
	awk '
		/^[[:space:]]*procedure Handle_Signal$/ { handler = 1 }
		handler && !body && /^[[:space:]]*begin[[:space:]]*$/ {
			body = 1
			next
		}
		body && /^[[:space:]]*end Handle_Signal;/ { exit }
		body {
			sub (/--.*/, "")
			if ($0 !~ /^[[:space:]]*$/)
				print
		}
	' "$signals_body" |
	sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'
)
expected='Terminate_Current;
begin
pragma Debug
(Logger.Log_File ("Signal received - shutting down"));
Socket_L.Close;
Socket_C.Close;
exception
when others => null;
end;
GNAT.OS_Lib.OS_Exit (Status => Integer (Ada.Command_Line.Success));'

if test "$actual" != "$expected"; then
	echo "signal handler contains fallible work before containment or exit" >&2
	printf '%s\n' "$actual" >&2
	exit 1
fi

# The C core already publishes the active process-group identity atomically.
# Do not reintroduce an independently maintained Ada running-state shadow.
if grep -E '(Set_Running|Stopped)' \
	"$signals_body" "$signals_spec" "$manager_body" >/dev/null
then
	echo "signal handler reintroduces redundant Ada request state" >&2
	exit 1
fi

echo "Signal shutdown contains the active group before immediate exit"
