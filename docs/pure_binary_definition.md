# Pure-Binary Definition

`buttercup-lite` current status:

1. `buttercup-lite` still does **not** fully restore all Buttercup mechanisms.
2. The current `binary-native seed proof` is real, but binary is **not yet** a fully parallel first-class entry equal to source.
3. The next step is to remove source contamination, complete the missing front-half mechanisms, and then return to medium/long validation.

## What counts as pure-binary

A task may be labeled `binary_mode = "pure_binary"` only when the binary path is driven by:

- a standalone binary file
- a binary execution input contract
  - `file`
  - `stdin`
  - `argv`
- `ida_mcp` / `idalib` analysis outputs
- binary runtime observations
  - execution manifests
  - traces
  - crash candidates
  - repro / PoV evidence

## What disqualifies pure-binary

If any of the following are used as binary seed/context drivers, the run is **not** pure-binary:

- `fuzz_main.c`
- any source file or source snippet
- source harness code
- source-side seeds as the primary seed source
- source-derived dict / options / harness metadata as the core semantic hint
- source program model context

## Required contamination report

Every binary task must write a contamination report with at least:

- `binary_mode`
- `source_context_used`
- `source_harness_used`
- `source_seed_imported_count`
- `source_dict_used`
- `source_options_used`
- `source_program_model_used`
- `pure_binary_eligible`

If any source contamination flag is true, the task must **not** claim `pure_binary`.

## Current baseline classification

The existing task `7d43dc4a-a0e7-4c0d-84b3-fa11980e1734` is:

- `binary-native seed proof = true`
- `binary_mode = "binary_native_proof"`
- **not** `pure_binary_complete`

Reason:

- its launcher/input semantics still came from source-derived compatibility assumptions
- it still sat on a `source_derived_binary` benchmark lane

