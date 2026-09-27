#!/bin/sh

set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
selector=$script_dir/select-maintained-tags.sh
verifier=$script_dir/verify-maintained-tag.sh
workflow=$script_dir/../workflows/release-integrity.yml
ci_workflow=$script_dir/../workflows/ci.yml
real_manifest=$script_dir/../maintained-release-tags
test_root=$(mktemp -d "${TMPDIR:-/tmp}/spawn-maintained-tags.XXXXXX")
trap 'rm -rf "$test_root"' EXIT HUP INT TERM

manifest=$test_root/manifest
repository_tags=$test_root/repository-tags
output=$test_root/output
tab=$(printf '\t')

list_repository_tags()
{
	git for-each-ref \
		--format='%(refname:strip=2)%09%(objectname)' refs/tags |
		LC_ALL=C sort
}

verify_registry()
{
	reviewed_manifest=$1
	list_repository_tags > "$repository_tags"
	"$selector" "$reviewed_manifest" "$repository_tags" > "$output"
	while IFS=$tab read -r tag expected_target expected_object; do
		"$verifier" "$tag" "$expected_target" "$expected_object"
	done < "$output"
}

# Exercise the reviewed production manifest and every published tag object.
verify_registry "$real_manifest"

# A reviewed future entry remains optional until its tag is published.
production_with_plan=$test_root/production-with-plan
cp "$real_manifest" "$production_with_plan"
printf 'v999.0.0\t%s\tplanned\t-\n' \
	3333333333333333333333333333333333333333 >> "$production_with_plan"
verify_registry "$production_with_plan"
if grep -F "v999.0.0" "$output" >/dev/null; then
	echo "absent planned tag was selected for verification" >&2
	exit 1
fi

target=1111111111111111111111111111111111111111
tag_object=2222222222222222222222222222222222222222

printf 'v0.1.0\t%s\tplanned\t-\n' "$target" > "$manifest"
: > "$repository_tags"
"$selector" "$manifest" "$repository_tags" > "$output"
test ! -s "$output"

printf 'v0.1.0\t%s\tpublished\t%s\n' \
	"$target" "$tag_object" > "$manifest"
if "$selector" "$manifest" "$repository_tags" > "$output" 2>&1;
then
	echo "missing published maintained tag was accepted" >&2
	exit 1
fi
grep -F "published maintained tag v0.1.0 is missing" "$output" \
	>/dev/null

printf 'v0.1.0\t%s\n' "$tag_object" > "$repository_tags"
"$selector" "$manifest" "$repository_tags" > "$output"
test "$(cat "$output")" = \
	"$(printf 'v0.1.0\t%s\t%s' "$target" "$tag_object")"

printf 'v9.9.9\t%s\n' "$tag_object" >> "$repository_tags"
if "$selector" "$manifest" "$repository_tags" > "$output" 2>&1;
then
	echo "undeclared repository tag was accepted" >&2
	exit 1
fi
grep -F "repository tag v9.9.9 is not declared" "$output" >/dev/null

printf 'v0.1.0\t%s\tpublished\t%s\n' \
	"$target" "$tag_object" > "$manifest"
printf 'v0.1.0\t%s\tpublished\t%s\n' \
	"$target" "$tag_object" >> "$manifest"
if "$selector" "$manifest" /dev/null > "$output" 2>&1;
then
	echo "duplicate maintained tag was accepted" >&2
	exit 1
fi
grep -F "duplicate entries" "$output" >/dev/null

printf 'v0.2.0-rc1\t%s\tplanned\t-\n' "$target" > "$manifest"
if "$selector" "$manifest" /dev/null > "$output" 2>&1;
then
	echo "non-stable maintained tag was accepted" >&2
	exit 1
fi
grep -F "invalid maintained-tag entry" "$output" >/dev/null

printf 'v0.2.0\tnot-a-commit\tplanned\t-\n' > "$manifest"
if "$selector" "$manifest" /dev/null > "$output" 2>&1;
then
	echo "invalid maintained target was accepted" >&2
	exit 1
fi
grep -F "invalid maintained-tag entry" "$output" >/dev/null

printf 'v0.2.0\t%s\tunknown\t-\n' "$target" > "$manifest"
if "$selector" "$manifest" /dev/null > "$output" 2>&1;
then
	echo "invalid maintained state was accepted" >&2
	exit 1
fi
grep -F "invalid maintained-tag entry" "$output" >/dev/null

printf 'v0.2.0\t%s\tplanned\t%s\n' \
	"$target" "$tag_object" > "$manifest"
if "$selector" "$manifest" /dev/null > "$output" 2>&1;
then
	echo "planned tag with reserved object was accepted" >&2
	exit 1
fi
grep -F "invalid maintained-tag object" "$output" >/dev/null

printf 'v0.2.0\t%s\tpublished\t-' "$target" > "$manifest"
if "$selector" "$manifest" /dev/null > "$output" 2>&1;
then
	echo "published tag without object was accepted" >&2
	exit 1
fi
grep -F "invalid maintained-tag object" "$output" >/dev/null

printf 'v0.3.0\tnot-a-commit\tplanned\t-' > "$manifest"
if "$selector" "$manifest" /dev/null > "$output" 2>&1;
then
	echo "invalid unterminated manifest row was ignored" >&2
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
approved_object=$(git -C "$tag_repo" rev-parse refs/tags/v0.1.0)
(
	cd "$tag_repo"
	"$verifier" v0.1.0 "$approved_target" "$approved_object"
)

# Rewriting only the annotation must fail even when the target stays fixed.
git -C "$tag_repo" tag -f -a v0.1.0 -m "rewritten annotation" \
	"$approved_target" >/dev/null
if (
	cd "$tag_repo"
	"$verifier" v0.1.0 "$approved_target" "$approved_object"
) > "$output" 2>&1; then
	echo "rewritten maintained annotation was accepted" >&2
	exit 1
fi
grep -F "expected $approved_object from the release registry" "$output" \
	>/dev/null

git -C "$tag_repo" commit -q --allow-empty -m "wrong target"
git -C "$tag_repo" tag -f -a v0.1.0 -m "moved annotation" >/dev/null
if (
	cd "$tag_repo"
	"$verifier" v0.1.0 "$approved_target" -
) > "$output" 2>&1; then
	echo "moved maintained tag was accepted" >&2
	exit 1
fi
grep -F "expected $approved_target" "$output" >/dev/null

git -C "$tag_repo" tag -f v0.1.0 "$approved_target" >/dev/null
if (
	cd "$tag_repo"
	"$verifier" v0.1.0 "$approved_target" -
) > "$output" 2>&1; then
	echo "lightweight maintained tag was accepted" >&2
	exit 1
fi
grep -F "is not annotated" "$output" >/dev/null

blob_target=$(printf 'not a commit\n' |
	git -C "$tag_repo" hash-object -w --stdin)
git -C "$tag_repo" tag -f -a v0.1.0 -m "blob target" \
	"$blob_target" >/dev/null
if (
	cd "$tag_repo"
	"$verifier" v0.1.0 "$blob_target" -
) > "$output" 2>&1; then
	echo "maintained tag with non-commit target was accepted" >&2
	exit 1
fi
grep -F "does not target a commit" "$output" >/dev/null

# The scheduled workflow is read-only and verifies canonical master directly.
grep -F "ref: master" "$workflow" >/dev/null
grep -F "permissions:" "$workflow" >/dev/null
grep -F "contents: read" "$workflow" >/dev/null
grep -F "select-maintained-tags.sh" "$workflow" >/dev/null
grep -F "verify-maintained-tag.sh" "$workflow" >/dev/null
if grep -F "contents: write" "$workflow" >/dev/null ||
   grep -Fi "codelabs" "$workflow" >/dev/null; then
	echo "release integrity workflow still synchronizes an external remote" >&2
	exit 1
fi

grep -F -- "- master" "$ci_workflow" >/dev/null
grep -F -- "- abuild-gh" "$ci_workflow" >/dev/null
if grep -F "GitHub-only overlay" "$ci_workflow" >/dev/null; then
	echo "canonical CI still enforces the former overlay boundary" >&2
	exit 1
fi

echo "Maintained release-tag integrity policy verified"
