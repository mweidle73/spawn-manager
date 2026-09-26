# Spawn Manager Agent Guidance

Keep changes focused and preserve the separation between the tasking Ada
caller and the dedicated process manager.

## Relevant documentation

- Use `README.md` for the component overview, supported platform and normal
  build, test and installation commands.
- Read `doc/protocol-v1.md` when changing request or result fields, validation,
  transport bounds or stream handling.
- Read `doc/lifecycle-v1.md` when changing processes, descriptors, signals,
  timeouts, cancellation, cgroup callbacks or pool cleanup.
- Update `CHANGELOG.md` for user- or integrator-visible changes. Keep planned
  release work under `Unreleased` until the release tag is created.

## Development

- Work in a clean, durable worktree outside temporary directories.
- Build with `make -j8`, then run `make tests` without Make-level parallelism.
  The tests use disposable local fixtures and have no production access.
- Run `make doc` after changing Markdown, Pages links or documentation build
  rules. Run `make perf` only for execution-path or performance work.
- Do not add generated sign-off or co-author trailers to commits.

## Architecture invariants

- The separate `spawn_manager` process is the only `fork`/`exec` boundary.
  Tasking callers communicate with it over Unix-domain sockets.
- The command-string API retains `/bin/bash -o pipefail -c` behavior and the
  manager environment. Structured requests retain exact executable, argument,
  replacement-environment, working-directory, stream and result semantics.
- Protocol version 1 is fixed and fail-closed. Wire changes require an explicit
  new version, updated format documentation and independent golden-byte tests.
- The post-`fork` child enters no Ada runtime code before `execve` or `_exit`.
  Keep the C boundary small, readable and limited to async-signal-safe child
  operations; explain non-obvious ownership and cleanup steps in comments.
- Lifecycle uncertainty is fail-closed. Setup, transport, reset, signal,
  process-group or reap failures must not expose an uncertain manager for
  reuse.
- Preserve short relative socket addresses on the wire and separately captured
  absolute cleanup paths. Preserve mandatory `no_new_privs` for both request
  types unless a future protocol version defines a reviewed exception.

## Branch and release policy

- `master` mirrors the Codelabs upstream. `abuild` is the exact source revision
  consumed by Abuild. `abuild-gh` may differ from `abuild` only below
  `.github/`.
- Component releases use annotated stable tags named `vMAJOR.MINOR.PATCH`.
  Pure test or documentation changes do not require a release tag.
- Historical 0.1.x tags follow Abuild's maintained Gitlink sequence even where
  that sequence moved between Spawn Manager branches.

## Code review rules

1. Reject changes that move `fork` into a tasking caller, enter Ada after
   `fork`, or introduce non-async-signal-safe child work before `execve`.
2. Reject silent shell, argv, environment, stream, error-result or wire-format
   regressions. Require the corresponding compatibility or golden-byte test.
3. Reject any lifecycle path that can reuse a manager after uncertain setup,
   containment, signaling or reaping, or that regresses socket-length and
   `no_new_privs` guarantees.
