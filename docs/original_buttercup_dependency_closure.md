**Original Buttercup Dependency Closure**

前提：
- 当前还不能宣称“原版 Buttercup 各大机制都已严格实现”。
- 当前还不能宣称“原版各 pod 之间复杂依赖已经被完整解决”。
- 当前只能说：主骨架、前半主链、部分 live mechanism 已成立。
- protocol 只保留 formal slot，不再继续扩展。

| Plane / Pod / Workflow Stage | 原版对应 | Lite 对应 | 状态 | 已活依赖边 | 仍缺依赖边 | 证据 task id / manifest |
|---|---|---|---|---|---|---|
| task ingress | task ingress / challenge submit | `apps/api_server`, `TaskSpec`, submit scripts | 部分对齐 | `task ingress -> downloader` | 还没有原版级 challenge bundle normalization | `21cb5356-86cb-4bf1-990c-8b1d337e553c` / `task.json` |
| downloader | repo/binary/tooling fetch pod | `apps/workers/downloader/main.py`, `core/planning/imports.py` | 部分对齐 | `source.uri + fuzz_tooling_url -> normalized imports` | 还没有完整 challenge artifact federation | `21cb5356-86cb-4bf1-990c-8b1d337e553c` / `runtime/import_manifest.json` |
| task server / lifecycle | task server / lifecycle service | `TaskStateStore`, worker status transitions, campaign worker | 部分对齐 | `READY -> scheduler -> queued worker statuses`, `campaign heartbeat/checkpoint` | 还没有原版那种统一 cancellation / reconciliation plane | `51f88da9-59f3-4e97-a0db-20006d345c4c` / `runtime/campaign_manifest.json` |
| scheduler | scheduler / arbitration pod | `apps/workers/scheduler/main.py`, `core/campaign/scheduler.py`, `core/campaign/budgeting.py` | 部分对齐 | `coverage -> scheduler`, `patch/reflection -> campaign arbitration` | 还没有原版完整多-plane resource market | `48d7752b-0150-46a4-9aad-12c24f7fae79` / `runtime/global_arbitration_manifest.json` |
| program model / context plane | program model / context services | `apps/workers/program_model/main.py`, `core/seed/context_retriever.py`, `core/binary_seed/context_retriever.py` | 部分对齐 | `source index -> seed context`, `binary analysis -> binary slice context` | 还没有统一 source/binary context plane with patch reuse | `d15e7148-1f38-4536-9487-d6346e07afb6`, `ee48d355-ce4c-4417-87a4-81fb415c4fd2` |
| build plane | build matrix / builder pods | `apps/workers/builder/main.py`, `core/builder/fresh_build.py`, `core/builder/contracts.py` | 部分对齐 | `planner contract -> builder`, `patch build -> QE` | 还没有原版 coverage/fuzzer/tracer 全矩阵编排 | `288ead13-ae9d-4fd1-81af-79b08edddd5a`, `37f9ebfe-0c89-4541-98fc-2cda98cf86e9` |
| fuzz plane | fuzzing pods | `apps/workers/fuzzer/main.py`, `apps/workers/binary_execution/main.py` | 部分对齐 | `seed -> fuzz`, `binary seed -> binary execution` | pure-binary 还不是原版强度 fuzz plane | `51f88da9-59f3-4e97-a0db-20006d345c4c`, `12e3a3bd-c631-488a-be4c-ddf5b3070f0b` |
| coverage plane | coverage bot / coverage feedback | `core/campaign/coverage_feedback.py` | 部分对齐 | `real snapshot -> feedback -> scheduler -> execution plan mutation` | binary 仍是 coverage proxy，非 full coverage bot | `d42c8360-27f0-4fa3-add5-873865b5816c`, `3a472e80-0881-45b7-909b-2e5b2f3e0096` / `coverage/coverage_manifest.json` |
| tracer plane | tracer pods | `apps/workers/tracer/main.py`, `core/tracer/*` | 部分对齐 | `raw crash -> traced crash -> signature` | 还没有 patch-local trace prioritization back into tracer selection | `d15e7148-1f38-4536-9487-d6346e07afb6` / `trace/trace_manifest.json` |
| PoV reproducer plane | repro / PoV confirm pods | `apps/workers/reproducer/main.py`, `core/reproducer/*` | 部分对齐 | `traced crash -> repro -> pov -> patch priority` | 还没有 accepted-patch replay 回灌 campaign suppression 的丰富策略 | `d15e7148-1f38-4536-9487-d6346e07afb6` / `pov/repro_manifest.json` |
| seed-gen plane | SEED_INIT / VULN_DISCOVERY / SEED_EXPLORE | `apps/workers/seed/main.py`, `apps/workers/binary_seed/main.py`, `core/seed_strategy/*` | 部分对齐 | `coverage stall -> seed mode switch -> downstream fuzz/execution` | 还没有原版完整探索/利用/跨-plane seed economy | `51f88da9-59f3-4e97-a0db-20006d345c4c`, `12e3a3bd-c631-488a-be4c-ddf5b3070f0b` |
| patch / QE / reflection plane | patch / QE / reflection pods | `apps/workers/patch/main.py`, `core/patch_plane/state_machine.py`, `core/patch_priority/*` | 部分对齐 | `pov -> patch request -> build -> QE -> reflection -> arbitration` | 还没有 accepted patch，且没有完整 multi-agent patch synthesis | `37f9ebfe-0c89-4541-98fc-2cda98cf86e9`, `a2d64084-72dd-4ec9-b5b8-3e66dd304bd2` |
| protocol plane | protocol adapter / protocol pods | `core/protocol/*`, `apps/workers/protocol_execution/main.py` | 未对齐 | formal slot / lifecycle compatibility | protocol-native behavior 全部缺失，且本阶段 out-of-scope | `0ba33aea-e1bf-41b4-b69c-6aea4149d487` / `runtime/protocol_execution_manifest.json` |
| infra / observability plane | manifests / evidence / reports / checkpoints | `core/storage/layout.py`, campaign reports, coverage manifests, patch manifests | 严格对齐 | 大部分主链都有 evidence / checkpoint / summary | 仍缺原版全集群级 observability，但 lite 范围内闭包较好 | `51f88da9-59f3-4e97-a0db-20006d345c4c`, `48d7752b-0150-46a4-9aad-12c24f7fae79`, `37f9ebfe-0c89-4541-98fc-2cda98cf86e9` |

**当前最关键的闭包判断**

- `coverage -> scheduler -> seed/fuzz/binary_execution plan`：已活，但 binary 仍是 proxy 级。
- `pov -> patch priority -> patch/QE/reflection -> campaign arbitration`：已活，但 accepted patch 尚未出现。
- `source / pure_binary` 两条主路径都已进入同一 campaign / scheduler / evidence 骨架：已活。
- `protocol` 只有 formal slot：不继续扩展，视为 out-of-scope。
