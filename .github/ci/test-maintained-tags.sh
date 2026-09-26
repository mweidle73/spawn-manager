#!/bin/sh

set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
selector=$script_dir/select-maintained-tags.sh
workflow=$script_dir/../workflows/upstream-monitor.yml
test_root=$(mktemp -d "${TMPDIR:-/tmp}/spawn-maintained-tags.XXXXXX")
trap 'rm -rf "$test_root"' EXIT HUP INT TERM

manifest=$test_root/manifest
mirror=$test_root/mirror
upstream=$test_root/upstream
output=$test_root/output

printf 'v0.1.0\n' > "$manifest"
printf 'v0.1.0\tmaintained-object\n' > "$mirror"
: > "$upstream"
"$selector" "$manifest" "$mirror" "$upstream" > "$output"
test "$(cat "$output")" = v0.1.0

# An exact upstream tag needs no maintained ownership declaration.
printf 'v1.0.0\tshared-object\n' > "$mirror"
printf 'v1.0.0\tshared-object\n' > "$upstream"
"$selector" "$manifest" "$mirror" "$upstream" > "$output"
test ! -s "$output"

# A deleted upstream tag becomes mirror-only and must not be reclassified.
printf 'v1.0.0\tformer-upstream-object\n' > "$mirror"
: > "$upstream"
if "$selector" "$manifest" "$mirror" "$upstream" > "$output" 2>&1;
then
	echo "undeclared mirror-only tag was accepted" >&2
	exit 1
fi
grep -F "v1.0.0 is not declared as maintained" "$output" >/dev/null

printf 'v0.1.0\nv0.1.0\n' > "$manifest"
if "$selector" "$manifest" "$mirror" "$upstream" > "$output" 2>&1;
then
	echo "duplicate maintained tag was accepted" >&2
	exit 1
fi
grep -F "duplicate entries" "$output" >/dev/null

printf 'v0.2.0-rc1\n' > "$manifest"
if "$selector" "$manifest" "$mirror" "$upstream" > "$output" 2>&1;
then
	echo "non-stable maintained tag was accepted" >&2
	exit 1
fi
grep -F "invalid entries" "$output" >/dev/null

# The scheduled job needs overlay policy files but must still mirror master.
grep -F "ref: abuild-gh" "$workflow" >/dev/null
grep -F "mirror_ref=refs/remotes/origin/master" "$workflow" >/dev/null
grep -F 'mirror_sha=$(git rev-parse "$mirror_ref")' "$workflow" >/dev/null
if grep -F 'mirror_sha=$(git rev-parse HEAD)' "$workflow" >/dev/null; then
	echo "upstream monitor compares its overlay checkout instead of master" >&2
	exit 1
fi

echo "Maintained release-tag provenance policy verified"
