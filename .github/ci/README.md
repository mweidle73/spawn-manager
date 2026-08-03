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

The generated HTML landing page is written to `doc/html/index.html`.

Set `SPAWN_CI_IMAGE` to override the local image name,
`DOCKER_PLATFORM` to override the default `linux/amd64` platform, and
`SPAWN_CI_NETWORK` to override the default `none` network mode.

The weekly upstream monitor compares both `master` and all tag refs with
Codelabs. The upstream currently has no tags, so the first new tag will fail
the workflow for manual review; the workflow never creates or updates tags.
