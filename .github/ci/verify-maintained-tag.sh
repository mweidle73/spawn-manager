#!/bin/sh

set -eu

tag=${1:?tag name is required}
expected_target=${2:?expected target commit is required}
expected_object=${3:--}
tag_ref=refs/tags/$tag

if ! git show-ref --verify --quiet "$tag_ref"; then
	echo "maintained tag $tag is missing after fetch" >&2
	exit 1
fi
if test "$(git cat-file -t "$tag_ref")" != tag; then
	echo "maintained tag $tag is not annotated" >&2
	exit 1
fi

actual_object=$(git rev-parse "$tag_ref")
if test "$expected_object" != - &&
   test "$actual_object" != "$expected_object"; then
	echo "maintained tag $tag has object $actual_object," >&2
	echo "expected $expected_object from the release registry" >&2
	exit 1
fi

actual_target=$(git rev-parse "$tag_ref^{}")
if test "$(git cat-file -t "$actual_target")" != commit; then
	echo "maintained tag $tag does not target a commit" >&2
	exit 1
fi
if test "$actual_target" != "$expected_target"; then
	echo "maintained tag $tag has target $actual_target," >&2
	echo "expected $expected_target from the release registry" >&2
	exit 1
fi
