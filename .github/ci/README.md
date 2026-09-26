# Spawn Manager GitHub CI environment

This repository is a GitHub mirror/fork of Spawn Manager from
[codelabs.ch](https://www.codelabs.ch/). The GitHub-only `abuild-gh` branch
extends the exact source revision consumed by Abuild with CI configuration.
The three long-lived branches have distinct roles:

- `master` mirrors the Codelabs upstream repository.
- `abuild` is the exact Spawn Manager revision pinned by Abuild `master`.
- `abuild-gh` adds only files below `.github/` to `abuild`.

The `run` helper builds a minimal Debian Trixie image and starts it as the
invoking host user. Its root filesystem is read-only, its network is disabled
by default after the image build, and the repository is mounted read-write at
`/work`. GitHub Actions and local development use the same entry point.

Run the complete build and test sequence from the Spawn Manager repository
root:

```sh
.github/ci/run /bin/sh -c '
  set -eu
  test "$(id -u)" -ne 0
  make clean
  make -j8
  make tests
'
```

The test runner is deliberately invoked without GNU Make parallelism so its
output and failure ordering stay deterministic. With no command, `run` opens
an interactive shell in `/work`:

```sh
.github/ci/run
```

Build the documentation with the same image:

```sh
.github/ci/run /bin/sh -c '
  set -eu
  test "$(id -u)" -ne 0
  make doc
'
```

The generated HTML landing page, changelog, work queue and version 1 protocol
and lifecycle contracts are written below `doc/html/`.

Set `SPAWN_CI_IMAGE` to override the local image name,
`DOCKER_PLATFORM` to override the default `linux/amd64` platform, and
`SPAWN_CI_NETWORK` to override the default `none` network mode.

The weekly upstream monitor compares `master` and every Codelabs-owned tag ref
with Codelabs. It mirrors those authoritative upstream tag objects exactly,
regardless of whether they represent an Abuild release.

Annotated stable semantic-version tags maintained for the Abuild integration
may exist only on GitHub when their exact names, peeled target commits and
`planned` or `published` states are declared in
`.github/maintained-release-tags`. The workflow never synthesizes or rewrites
a tag object. It preserves GitHub-only tags and may copy a declared
upstream-first tag object to GitHub after validating its annotation and target.
If a declared name already exists on both remotes, the complete annotated tag
objects must match; equal peeled commits do not excuse different release
annotations. A planned tag may be absent. A published tag must remain on
GitHub. An undeclared mirror-only tag, lightweight tag or mismatched target
blocks the sync. An upstream copy cannot hide deletion of a published GitHub
tag.

The manifest remains the release registry after the reconstructed 0.1.x
history. For each later release, including `v0.2.0`, use this order:

1. Finalize the source release commit and changelog on `abuild`.
2. Add the stable tag name, that commit's full object ID and state `planned` to
   `.github/maintained-release-tags` on `abuild-gh`, then review and merge the
   policy change.
3. Create and publish the annotated tag at exactly that source commit.
4. Change its manifest state to `published` in a reviewed follow-up. That
   state makes later deletion a synchronization failure.

Do not reserve a placeholder object ID before the release commit is final.
