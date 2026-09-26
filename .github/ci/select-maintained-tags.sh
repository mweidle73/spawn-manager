#!/bin/sh

set -eu

manifest=${1:?maintained-tag manifest is required}
mirror_tags=${2:?mirror-tag inventory is required}
upstream_tags=${3:?upstream-tag inventory is required}
stable_version='^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'
commit_id='^[0-9a-f]{40}$'

test -f "$manifest" || {
	echo "maintained-tag manifest is missing: $manifest" >&2
	exit 1
}

manifest_tags=$(
	while IFS=$(printf '\t') read -r tag target state extra; do
		if ! printf '%s\n' "$tag" | grep -Eq "$stable_version" ||
		   ! printf '%s\n' "$target" | grep -Eq "$commit_id" ||
		   { test "$state" != planned && test "$state" != published; } ||
		   test -n "$extra"; then
			echo "invalid maintained-tag entry: $tag" >&2
			exit 1
		fi
		printf '%s\n' "$tag"
	done < "$manifest"
) || exit 1

duplicates=$(printf '%s\n' "$manifest_tags" | LC_ALL=C sort | uniq -d)
if test -n "$duplicates"; then
	echo "maintained-tag manifest has duplicate entries:" >&2
	echo "$duplicates" >&2
	exit 1
fi

while IFS=$(printf '\t') read -r tag mirror_tag_sha; do
	test -n "$tag" || continue
	test -n "$mirror_tag_sha" || {
		echo "mirror tag $tag has no object ID" >&2
		exit 1
	}
	upstream_tag_sha=$(awk -F '\t' -v wanted="$tag" \
		'$1 == wanted { print $2 }' "$upstream_tags")
	if test -z "$upstream_tag_sha"; then
		if ! printf '%s\n' "$manifest_tags" | grep -Fxq "$tag"; then
			echo "mirror-only tag $tag is not declared as maintained" >&2
			exit 1
		fi
	fi
done < "$mirror_tags"

while IFS=$(printf '\t') read -r tag expected_target state; do
	mirror_tag_sha=$(awk -F '\t' -v wanted="$tag" \
		'$1 == wanted { print $2 }' "$mirror_tags")
	upstream_tag_sha=$(awk -F '\t' -v wanted="$tag" \
		'$1 == wanted { print $2 }' "$upstream_tags")
	if test "$state" = published && test -z "$mirror_tag_sha"; then
		echo "published maintained tag $tag is missing from the mirror" >&2
		exit 1
	elif test -n "$mirror_tag_sha"; then
		printf '%s\t%s\torigin\n' "$tag" "$expected_target"
	elif test -n "$upstream_tag_sha"; then
		printf '%s\t%s\tupstream\n' "$tag" "$expected_target"
	fi
done < "$manifest"
