#!/bin/sh

set -eu

manifest=${1:?maintained-tag manifest is required}
repository_tags=${2:?repository-tag inventory is required}
stable_version='^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'
object_id='^[0-9a-f]{40}$'
tab=$(printf '\t')

test -f "$manifest" || {
	echo "maintained-tag manifest is missing: $manifest" >&2
	exit 1
}

manifest_tags=$(
	while IFS=$tab read -r tag target state tag_object extra ||
	      test -n "$tag$target$state$tag_object$extra"; do
		if ! printf '%s\n' "$tag" | grep -Eq "$stable_version" ||
		   ! printf '%s\n' "$target" | grep -Eq "$object_id" ||
		   { test "$state" != planned && test "$state" != published; } ||
		   test -n "$extra"; then
			echo "invalid maintained-tag entry: $tag" >&2
			exit 1
		fi
		if test "$state" = planned && test "$tag_object" = -; then
			:
		elif test "$state" != published ||
		     ! printf '%s\n' "$tag_object" | grep -Eq "$object_id"; then
			echo "invalid maintained-tag object: $tag" >&2
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

while IFS=$tab read -r tag tag_object extra ||
      test -n "$tag$tag_object$extra"; do
	test -n "$tag" || continue
	if ! printf '%s\n' "$tag_object" | grep -Eq "$object_id" ||
	   test -n "$extra"; then
		echo "invalid repository-tag entry: $tag" >&2
		exit 1
	fi
	if ! printf '%s\n' "$manifest_tags" | grep -Fxq "$tag"; then
		echo "repository tag $tag is not declared as maintained" >&2
		exit 1
	fi
done < "$repository_tags"

while IFS=$tab read -r tag expected_target state expected_object ||
      test -n "$tag$expected_target$state$expected_object"; do
	actual_object=$(awk -F '\t' -v wanted="$tag" \
		'$1 == wanted { print $2 }' "$repository_tags")
	if test "$state" = published && test -z "$actual_object"; then
		echo "published maintained tag $tag is missing" >&2
		exit 1
	elif test -n "$actual_object"; then
		printf '%s\t%s\t%s\n' \
			"$tag" "$expected_target" "$expected_object"
	fi
done < "$manifest"
