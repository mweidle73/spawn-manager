#!/bin/sh

set -eu

tag=${1:?tag name is required}
expected_target=${2:?expected target commit is required}
tag_ref=refs/tags/$tag

if ! git show-ref --verify --quiet "$tag_ref"; then
	echo "maintained tag $tag is missing after fetch" >&2
	exit 1
fi
if test "$(git cat-file -t "$tag_ref")" != tag; then
	echo "maintained tag $tag is not annotated" >&2
	exit 1
fi

actual_target=$(git rev-parse "$tag_ref^{}")
if test "$(git cat-file -t "$actual_target")" != commit; then
	echo "maintained tag $tag does not target a commit" >&2
	exit 1
fi
if test "$actual_target" != "$expected_target"; then
	echo "maintained tag $tag has target $actual_target," >&2
	echo "expected $expected_target from Abuild's Gitlink history" >&2
	exit 1
fi
