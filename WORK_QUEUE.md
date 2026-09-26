# Spawn Manager Work Queue

This is the maintained list of accepted follow-up work after the initial
structured-execution delivery. It records concrete consumers and known
boundaries without silently extending protocol version 1. Assign a ticket and
define acceptance evidence before starting an item.

## Release 0.2.0 gates

- Complete the remaining native performance measurements on every release
  architecture and retain paired shell, structured-manager and direct-core
  medians.
- Review and publish the reconstructed annotated 0.1.x tags, then close the
  `Unreleased` changelog section and create the annotated `v0.2.0` tag.
- Verify the final Spawn Manager revision through Abuild's recursive checkout,
  archive, install, reference-product and user-interrupt system tests.

## Accepted follow-ups

### Shared output sink and Abuild `make` migration

Exec V1 has independent null-or-truncate stdout and stderr streams. Pointing
both at one pathname would open and truncate it twice and would not preserve
the historical ordered combined build log, so component `make` remains an
intentional shell caller.

Define and test one shared open-file-description stream policy, either as an
explicitly compatible V1 completion before release or as protocol V2. Preserve
ordered stdout/stderr, cgroup placement, complete argv logging and Ctrl-C
cleanup, then migrate `make -s -jN -C PATH` to structured execution.

### Remaining Abuild shell callers

Eleven production shell sites remain for configured scripts, pipelines or
append/merge behavior. Raw shell values require explicit quoting. After the
shared-stream decision, re-audit the allowlist and migrate every caller which
no longer needs shell syntax. Keep configured `runcmd` source explicit rather
than pretending it is argv data.

### Explicit privilege-gaining execution

Version 1 applies `no_new_privs` to every shell and structured request and has
no exception. Add an opt-in only for a concrete transformation which requires
privilege metadata during `execve`. Specify it in a new protocol contract and
require cgroup containment because privileged exec may clear the direct
leader's parent-death signal.

### Individual request cancellation

Version 1 cancels the complete pool through `Cleanup`; it has no request
identifier or single-request cancel operation. Add this only for a concrete
concurrent consumer. Define identity, races, result classification and manager
reuse before choosing a wire format.

### Descriptor-ceiling refresh

A failed `/proc/self/fd` scan selects the finite soft-limit fallback and caches
the safe result. This is safe but may retain slower descriptor cleanup after a
transient procfs failure. Measure a reproducible impact first. If material,
define a bounded retry or refresh rule without allowing a partial procfs scan
to lower the ceiling.

### Invalid-descriptor diagnostics

Transport deadline checks may win over `POLLNVAL`, changing diagnostic
specificity but not safety. Add a focused fault injection and reorder only if
the more precise diagnosis is stable across supported kernels.

Abuild-specific scheduling, real cgroup-provider validation and source
acquisition remain in Abuild's own plans and work queue. This component queue
records only the Spawn Manager contract needed by those consumers.
