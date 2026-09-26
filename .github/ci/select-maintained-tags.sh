#!/bin/sh

set -eu

manifest=${1:?maintained-tag manifest is required}
mirror_tags=${2:?mirror-tag inventory is required}
upstream_tags=${3:?upstream-tag inventory is required}
stable_version='^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'

test -f "$manifest" || {
	echo "maintained-tag manifest is missing: $manifest" >&2
	exit 1
}

invalid=$(grep -Ev "$stable_version" "$manifest" || true)
if test -n "$invalid"; then
	echo "maintained-tag manifest has invalid entries:" >&2
	echo "$invalid" >&2
	exit 1
fi

duplicates=$(LC_ALL=C sort "$manifest" | uniq -d)
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
		if ! grep -Fxq "$tag" "$manifest"; then
			echo "mirror-only tag $tag is not declared as maintained" >&2
			exit 1
		fi
		printf '%s\n' "$tag"
	fi
done < "$mirror_tags"
