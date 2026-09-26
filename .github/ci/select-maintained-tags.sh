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
	while IFS=$(printf '\t') read -r tag target extra; do
		if ! printf '%s\n' "$tag" | grep -Eq "$stable_version" ||
		   ! printf '%s\n' "$target" | grep -Eq "$commit_id" ||
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
		manifest_entry=$(awk -F '\t' -v wanted="$tag" \
			'$1 == wanted { print $1 "\t" $2 }' "$manifest")
		if test -z "$manifest_entry"; then
			echo "mirror-only tag $tag is not declared as maintained" >&2
			exit 1
		fi
		printf '%s\n' "$manifest_entry"
	fi
done < "$mirror_tags"
