# Buttercup-Lite Architecture Alignment

## 结论

当前实现仍然对齐 Buttercup 的主技术流，没有退化成几个临时 shell 脚本拼起来的 ad-hoc 系统。

系统主干仍然是：

- `task ingress -> scheduler/planning -> program model -> build -> seed -> fuzz/binary execution -> trace -> repro -> PoV -> patch reserved`

真正 benchmark-specific 的部分，已经被明确压在 adapter、benchmark config 和 execution binding 中，而不是混进主架构本体。

## 阶段映射

### 1. Task ingress / downloader

- 原版 Buttercup 角色：接收 challenge 输入，拉取源码/工件，归一化任务目录。
- 轻量版对应：
  - `apps/api_server/main.py`
  - `apps/workers/downloader/main.py`
  - `core/storage/layout.py`
  - `core/state/task_state.py`
- 轻量化：
  - 统一用 task dir + JSON manifest，不引入 protobuf/K8s ingress。
- 通用架构：
  - 任务建模、layout、状态推进、runtime manifest。
- benchmark-specific adapter：
  - benchmark config 只决定 metadata / import path，不改变 downloader 主逻辑。

### 2. Scheduler / planning

- 原版 Buttercup 角色：把 READY 任务拆成 program model、build、seed、fuzz、trace、repro 等执行计划。
- 轻量版对应：
  - `apps/workers/scheduler/main.py`
  - `core/planning/execution.py`
  - `core/planning/imports.py`
- 轻量化：
  - 用 JSON execution plan，优先支持 `fresh / import_assisted / hybrid`。
- 通用架构：
  - adapter resolution、stage planning、runtime/import manifest。
- benchmark-specific adapter：
  - `existing_*` 路径、`binary_analysis_backend`、launcher/wrapper 选择。

### 3. Program model

- 原版 Buttercup 角色：构建代码事实层，给 seed/context/root cause 使用。
- 轻量版对应：
  - `apps/workers/program_model/main.py`
  - `core/program_model/*`
- 轻量化：
  - 保留 cscope/ctags/codequery/tree-sitter 的轻量可用子集。
- 通用架构：
  - `index/manifest.json`、`symbols.json`、查询接口。
- benchmark-specific adapter：
  - `import_assisted` 时导入已有 index / src。

### 4. Build

- 原版 Buttercup 角色：构建 fuzz/trace/repro 所需目标。
- 轻量版对应：
  - `apps/workers/builder/main.py`
  - `core/builder/import_scan.py`
  - `core/builder/fresh_build.py`
- 轻量化：
  - source-side 以 OSS-Fuzz 项目目录为主，binary-side 以 imported binary 为主。
- 通用架构：
  - `build/build_registry.json`
  - harness/dict/options/corpus zip 标准化。
- benchmark-specific adapter：
  - `cjson_read_fuzzer`
  - `glibc239_binary_launcher.sh`
  - `source_derived_binary`

### 5. Seed-gen

- 原版 Buttercup 角色：利用 program model + harness context 生成 testcase/seed。
- 轻量版对应：
  - `apps/workers/seed/main.py`
  - `core/seed/*`
- 轻量化：
  - 只实现 SeedInit 主路径，先输出 Python bytes 生成函数。
- 通用架构：
  - harness selection、context retrieval、LLM client、seed manifest。
- benchmark-specific adapter：
  - `cjson_read_fuzzer` prompt/context 偏向 JSON 输入；
  - imported corpus/seed 只是辅助路径。

### 6. Fuzzing / binary execution

- 原版 Buttercup 角色：持续执行 harness，扩 corpus，发现 crash。
- 轻量版对应：
  - source-side: `apps/workers/fuzzer/main.py`, `core/fuzz/*`
  - binary-side: `apps/workers/binary_execution/main.py`, `core/binary/runner.py`
- 轻量化：
  - source-side 走 libFuzzer。
  - binary-side 走 execution binding，不自造二进制分析器或独立 fuzz 系统。
- 通用架构：
  - queue、状态、manifest、distinct crash signature、campaign rounds。
- benchmark-specific adapter：
  - `fuzz_main.c` 只属于 launcher semantics source，不是架构本体。
  - `glibc239_binary_launcher.sh` 只属于当前 cJSON source-derived binary 绑定。

### 7. Tracer

- 原版 Buttercup 角色：结构化重放 crash，提炼 crash_type/crash_state/signature。
- 轻量版对应：
  - `apps/workers/tracer/main.py`
  - `core/tracer/*`
  - binary bridge: `core/binary/trace_bridge.py`
- 轻量化：
  - 统一 ASan/stacktrace 解析，source/binary 共用 signature 逻辑。
- 通用架构：
  - `trace/traced_crashes/*.json`
  - `trace/trace_manifest.json`
  - `trace/dedup_index.json`
- benchmark-specific adapter：
  - binary path通过 `argv_template` / `input_mode=file` 做 bridge。

### 8. Reproducer / PoV

- 原版 Buttercup 角色：多次重放确认稳定性，生成 PoV。
- 轻量版对应：
  - `apps/workers/reproducer/main.py`
  - `core/reproducer/*`
  - binary bridge: `core/binary/repro_bridge.py`
- 轻量化：
  - 不做 patch，只做稳定重放和 PoV inventory。
- 通用架构：
  - `pov/repro_manifest.json`
  - `pov/confirmed/*.json`
  - source/binary 共用 PoV schema，binary 扩展 provenance 字段。
- benchmark-specific adapter：
  - `target_mode=binary`
  - `binary_provenance=source_derived_binary`

### 9. Patch reserved

- 原版 Buttercup 角色：补丁生成与验证。
- 轻量版对应：
  - API/status/directory 预留
- 当前状态：
  - reserved only，尚未实现。

## 主架构 vs benchmark 适配

### 主架构

- task / queue / state / manifest 体系
- adapter resolution + execution planning
- worker 拆分
- program model
- seed / fuzz / trace / repro / campaign / inventory
- source-side 与 binary-side 共用 signature / attribution / reporting

### benchmark-specific adapter

- `cjson_read_fuzzer`
- `fuzz_main.c`
- `glibc239_binary_launcher.sh`
- `source_derived_binary`
- `benchmarks/cjson_injected/*`

这些属于 benchmark execution binding，不是 Buttercup-lite 主架构本体。

## 尚未完成

- pure-binary / black-box binary benchmark
- protocol 路径
- patch pipeline
- 更完整的 root cause / auto patch / protocol orchestration

