#!/bin/sh

set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
selector=$script_dir/select-maintained-tags.sh
verifier=$script_dir/verify-maintained-tag.sh
workflow=$script_dir/../workflows/upstream-monitor.yml
test_root=$(mktemp -d "${TMPDIR:-/tmp}/spawn-maintained-tags.XXXXXX")
trap 'rm -rf "$test_root"' EXIT HUP INT TERM

manifest=$test_root/manifest
mirror=$test_root/mirror
upstream=$test_root/upstream
output=$test_root/output

approved_target=1111111111111111111111111111111111111111
printf 'v0.1.0\t%s\tplanned\n' "$approved_target" > "$manifest"
printf 'v0.1.0\tmaintained-object\n' > "$mirror"
: > "$upstream"
"$selector" "$manifest" "$mirror" "$upstream" > "$output"
test "$(cat "$output")" = \
	"$(printf 'v0.1.0\t%s\torigin' "$approved_target")"

# An exact upstream tag needs no maintained ownership declaration.
printf 'v1.0.0\tshared-object\n' > "$mirror"
printf 'v1.0.0\tshared-object\n' > "$upstream"
"$selector" "$manifest" "$mirror" "$upstream" > "$output"
test ! -s "$output"

# A later release uses the same policy and is checked if it appears upstream
# before the reviewed GitHub tag is published.
future_target=2222222222222222222222222222222222222222
printf 'v0.2.0\t%s\tplanned\n' "$future_target" > "$manifest"
: > "$mirror"
printf 'v0.2.0\tupstream-object\n' > "$upstream"
"$selector" "$manifest" "$mirror" "$upstream" > "$output"
test "$(cat "$output")" = \
	"$(printf 'v0.2.0\t%s\tupstream' "$future_target")"

# Once present on both sides, the mirror copy is the verification source.
printf 'v0.2.0\tshared-object\n' > "$mirror"
printf 'v0.2.0\tshared-object\n' > "$upstream"
"$selector" "$manifest" "$mirror" "$upstream" > "$output"
test "$(cat "$output")" = \
	"$(printf 'v0.2.0\t%s\torigin' "$future_target")"

# A planned tag may be absent; a published tag may not disappear from GitHub.
: > "$mirror"
: > "$upstream"
"$selector" "$manifest" "$mirror" "$upstream" > "$output"
test ! -s "$output"
printf 'v0.2.0\t%s\tpublished\n' "$future_target" > "$manifest"
if "$selector" "$manifest" "$mirror" "$upstream" > "$output" 2>&1;
then
	echo "missing published maintained tag was accepted" >&2
	exit 1
fi
grep -F "published maintained tag v0.2.0 is missing" "$output" >/dev/null

# An upstream copy must not hide deletion of the published GitHub ref.
printf 'v0.2.0\tupstream-object\n' > "$upstream"
if "$selector" "$manifest" "$mirror" "$upstream" > "$output" 2>&1;
then
	echo "upstream copy replaced a missing published mirror tag" >&2
	exit 1
fi
grep -F "published maintained tag v0.2.0 is missing" "$output" >/dev/null

printf 'v0.2.0\tmirror-object\n' > "$mirror"
"$selector" "$manifest" "$mirror" "$upstream" > "$output"
test "$(cat "$output")" = \
	"$(printf 'v0.2.0\t%s\torigin' "$future_target")"

# A deleted upstream tag becomes mirror-only and must not be reclassified.
printf 'v1.0.0\tformer-upstream-object\n' > "$mirror"
: > "$upstream"
if "$selector" "$manifest" "$mirror" "$upstream" > "$output" 2>&1;
then
	echo "undeclared mirror-only tag was accepted" >&2
	exit 1
fi
grep -F "v1.0.0 is not declared as maintained" "$output" >/dev/null

printf 'v0.1.0\t%s\tplanned\nv0.1.0\t%s\tplanned\n' \
	"$approved_target" "$approved_target" > "$manifest"
if "$selector" "$manifest" "$mirror" "$upstream" > "$output" 2>&1;
then
	echo "duplicate maintained tag was accepted" >&2
	exit 1
fi
grep -F "duplicate entries" "$output" >/dev/null

printf 'v0.2.0-rc1\t%s\tplanned\n' "$approved_target" > "$manifest"
if "$selector" "$manifest" "$mirror" "$upstream" > "$output" 2>&1;
then
	echo "non-stable maintained tag was accepted" >&2
	exit 1
fi
grep -F "invalid maintained-tag entry" "$output" >/dev/null

printf 'v0.2.0\tnot-a-commit\tplanned\n' > "$manifest"
if "$selector" "$manifest" "$mirror" "$upstream" > "$output" 2>&1;
then
	echo "invalid maintained target was accepted" >&2
	exit 1
fi
grep -F "invalid maintained-tag entry" "$output" >/dev/null

printf 'v0.2.0\t%s\tunknown\n' "$approved_target" > "$manifest"
if "$selector" "$manifest" "$mirror" "$upstream" > "$output" 2>&1;
then
	echo "invalid maintained publication state was accepted" >&2
	exit 1
fi
grep -F "invalid maintained-tag entry" "$output" >/dev/null

tag_repo=$test_root/tag-repository
git init -q "$tag_repo"
git -C "$tag_repo" config user.name "Spawn Manager CI"
git -C "$tag_repo" config user.email "spawn-manager@example.invalid"
git -C "$tag_repo" commit -q --allow-empty -m "approved target"
approved_target=$(git -C "$tag_repo" rev-parse HEAD)
git -C "$tag_repo" tag -a v0.1.0 -m "approved annotation"
(
	cd "$tag_repo"
	"$verifier" v0.1.0 "$approved_target"
)

git -C "$tag_repo" commit -q --allow-empty -m "wrong target"
git -C "$tag_repo" tag -f -a v0.1.0 -m "moved annotation" >/dev/null
if (
	cd "$tag_repo"
	"$verifier" v0.1.0 "$approved_target"
) > "$output" 2>&1; then
	echo "moved maintained tag was accepted" >&2
	exit 1
fi
grep -F "expected $approved_target" "$output" >/dev/null

# An upstream-first future tag is selected and then rejected on a wrong target.
git -C "$tag_repo" tag -a v0.2.0 -m "wrong upstream annotation"
printf 'v0.2.0\t%s\tplanned\n' "$approved_target" > "$manifest"
: > "$mirror"
printf 'v0.2.0\tupstream-tag-object\n' > "$upstream"
"$selector" "$manifest" "$mirror" "$upstream" > "$output"
IFS=$(printf '\t') read -r selected_tag selected_target selected_source \
	< "$output"
test "$selected_source" = upstream
if (
	cd "$tag_repo"
	"$verifier" "$selected_tag" "$selected_target"
) > "$output" 2>&1; then
	echo "wrong upstream-first maintained tag was accepted" >&2
	exit 1
fi
grep -F "expected $approved_target" "$output" >/dev/null

git -C "$tag_repo" tag -f v0.1.0 "$approved_target" >/dev/null
if (
	cd "$tag_repo"
	"$verifier" v0.1.0 "$approved_target"
) > "$output" 2>&1; then
	echo "lightweight maintained tag was accepted" >&2
	exit 1
fi
grep -F "is not annotated" "$output" >/dev/null

blob_target=$(printf 'not a commit\n' | git -C "$tag_repo" hash-object -w --stdin)
git -C "$tag_repo" tag -f -a v0.1.0 -m "blob target" "$blob_target" \
	>/dev/null
if (
	cd "$tag_repo"
	"$verifier" v0.1.0 "$blob_target"
) > "$output" 2>&1; then
	echo "maintained tag with non-commit target was accepted" >&2
	exit 1
fi
grep -F "does not target a commit" "$output" >/dev/null

# The scheduled job needs overlay policy files but must still mirror master.
grep -F "ref: abuild-gh" "$workflow" >/dev/null
grep -F "mirror_ref=refs/remotes/origin/master" "$workflow" >/dev/null
grep -F 'mirror_sha=$(git rev-parse "$mirror_ref")' "$workflow" >/dev/null
grep -F 'while IFS=$'"'"'\t'"'"' read -r tag expected_target tag_source' \
	"$workflow" >/dev/null
if grep -F 'mirror_sha=$(git rev-parse HEAD)' "$workflow" >/dev/null; then
	echo "upstream monitor compares its overlay checkout instead of master" >&2
	exit 1
fi

echo "Maintained release-tag provenance policy verified"
