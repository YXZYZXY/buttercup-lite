# Buttercup-Lite Lightweight Archive Note

This archive is a lightweight snapshot of the `buttercup-lite` repository.

It intentionally excludes several large runtime and tooling directories so the
archive is suitable for transfer and code review, while still preserving the
main source tree, scripts, manifests, and documentation.

## Current Archive Policy

The archive keeps the directory markers for the large local-only directories
where practical, but excludes their contents. This means a restored tree still
shows that the directories exist, while avoiding bundling local task state,
third-party tool installs, generated build payloads, and temporary scratch
artifacts.

This policy is intended for source-code archival, not for preserving a complete
runtime workspace. To resume previous campaigns exactly, keep the excluded
directories separately.

## Excluded Directories

### `data/`

This directory is the main task runtime data root. It is excluded because it is
the largest and most fast-growing workspace in the project.

Typical contents include:

- `data/tasks/<task-id>/`
  - per-task working directories
  - downloaded source trees
  - imported OSS-Fuzz project assets
  - build outputs
  - generated seeds and corpora
  - crashes, traces, repro artifacts, confirmed PoVs
  - patch attempts and QE outputs
  - manifests and reports written during each worker stage
- `data/datasets/`
  - packaged source-derived-binary datasets
  - opaque-binary-like packages
  - sidecar metadata and visibility-constraint files

Why excluded:

- it contains volatile experiment/runtime state rather than stable source code
- it can grow very quickly across repeated source/binary campaigns
- it may contain large corpora, crash samples, extracted archives, and copied
  build outputs
- in this workspace it has grown to well over 100 GB

### `ida_pro/`

This directory contains the local IDA Pro installation and related files used
for headless binary analysis.

Typical contents include:

- IDA executables such as `idat`, `idat64`, or related launchers
- bundled IDA Python / IDALib runtime files
- processor modules, loaders, plugins, signatures, and resources
- decompiler components when present

Why excluded:

- it is a heavyweight third-party tool installation
- it is environment-specific
- it should be managed separately from the repo snapshot
- in this workspace it is hundreds of MB

### `.toolchains/`

This directory contains locally provisioned build toolchains and compiler
runtime dependencies used to make source builds reproducible without relying on
the host system package set.

Typical contents include:

- clang / llvm binaries
- libFuzzer and sanitizer runtimes
- cmake / ctest / cpack and related build tools
- sysroot files, locale archives, libc/libstdc++ runtime pieces
- cscope / ctags / codequery helper tooling when installed into the local
  prefix

Why excluded:

- it is very large
- it is machine-specific and reproducible separately
- it contains mostly binary tool payload rather than repository logic
- in this workspace it is currently around the low-GB range

### `runtime/`

This directory stores transient runtime support files outside per-task data
roots.

Typical contents include:

- temporary launch/runtime state
- short-lived execution helpers
- intermediate operational outputs produced during local runs

Why excluded:

- it is derived state
- it is not needed to understand the source tree

### `tmp/`

This directory stores ad hoc temporary files created during local debugging,
experiments, replay setup, and script execution.

Typical contents include:

- extracted temporary artifacts
- one-off intermediate files
- scratch outputs from local verification commands

Why excluded:

- it is disposable
- it is not part of the stable project source

### `tmp_ida_test/`

This directory contains small temporary IDA-oriented smoke-test artifacts and
local validation outputs.

Typical contents include:

- temporary headless IDA test outputs
- one-off binary-analysis verification files
- scratch manifests used while checking IDA integration

Why excluded:

- it is transient debug state
- it is not required to understand or restore the repository source
- it should not be versioned into a source snapshot

### `tmp_phase55_xml/`

This is a temporary experiment/debug directory used during XML-oriented local
analysis and verification work.

Typical contents include:

- temporary XML inputs
- replay artifacts
- scratch outputs tied to a specific debug phase

Why excluded:

- it is phase-specific scratch state
- it is not required for the repository snapshot

### `tmp_phase55_screen/`

This is a large temporary experiment/debug directory associated with screen
captures, staged artifacts, and other intermediate outputs from a prior local
investigation phase.

Typical contents include:

- large temporary outputs
- staged screenshots or screen-derived artifacts
- phase-specific scratch files and extracted data

Why excluded:

- it is not source code
- it contributes significant bulk
- it is tied to one local debugging phase rather than the reusable project

### Python caches and generated bytecode

The archive excludes generated Python cache files such as:

- `__pycache__/`
- `*.pyc`
- `.pytest_cache/`

Why excluded:

- they are derived files
- they are not required to run from source
- they can make archive diffs noisy without adding useful state

### `.git/`

If present, repository VCS metadata is excluded from the lightweight archive.

Why excluded:

- it is not needed for source review or code handoff
- it can noticeably increase archive size
- this archive is intended as a source snapshot rather than a full VCS clone

### Old local archive files

The archive excludes nested archive files if any are present inside the project
tree, such as:

- `*.tar`
- `*.tar.gz`
- `*.tgz`
- `*.zip`

Why excluded:

- they can accidentally re-embed previous snapshots
- they are a common reason for archive size explosions

## What Remains In This Archive

This lightweight archive still includes the main repository logic, such as:

- `core/`
- `apps/`
- `scripts/`
- `tests/`
- `benchmarks/`
- `docs/`
- repo-level configuration files and manifests
- this note explaining what was intentionally omitted

## Purpose

This archive is intended to preserve:

- repository source code
- orchestration logic
- worker implementations
- manifests/report schemas
- scripts and configuration

without bundling:

- large local datasets
- heavyweight third-party binary tooling
- local compiler/toolchain payloads
- transient runtime/debug scratch data
