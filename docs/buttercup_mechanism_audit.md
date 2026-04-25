# Buttercup-Lite 机制审计

## 总结

当前 `buttercup-lite` **没有完整还原 Buttercup 的所有关键机制**。

目前只能诚实地说：

- 已经还原了主骨架中的若干关键阶段
- 已经跑通了 source-side strict-live、source-derived binary strict-live、ida_mcp binary analysis
- 但 **尚未完整还原 Buttercup 的 coverage-driven feedback、完整 Seed-Gen 任务家族、binary 作为完全并列入口、patcher 多智能体链路**

## 审计表

| 能力项 | 状态 | 当前证据 | 备注 |
|---|---|---|---|
| task ingress / downloader / scheduler | 已还原 | `apps/api_server/main.py` `apps/workers/downloader/main.py` `apps/workers/scheduler/main.py` | 轻量 JSON/task-dir 版本，非 K8s/protobuf 版 |
| build matrix（coverage / fuzzer / tracer） | 部分还原 | `apps/workers/builder/main.py` `core/builder/import_scan.py` `core/builder/fresh_build.py` | `fuzzer/tracer` 构建和 imported build 已有；`coverage build` 还未形成正式矩阵闭环 |
| program model / context retrieval | 部分还原 | `apps/workers/program_model/main.py` `core/program_model/*` `index/manifest.json` | source-side 有轻量 program model；binary-side context retrieval 本轮开始补 |
| AI seed generation 主链 | 部分还原 | `apps/workers/seed/main.py` `core/seed/*` | source-side `SEED_INIT` 已通；完整任务家族未还原 |
| coverage collection | 部分还原 | `core/campaign/coverage_feedback.py` `coverage/snapshots/*.json` | 当前是 libFuzzer progress proxy + corpus growth 的轻量版，不是完整 llvm-cov 体系 |
| coverage -> 调度/seedgen/fuzz 策略反馈闭环 | 部分还原 | `coverage/feedback_manifest.json` + runtime `coverage_feedback_action` | 已能因停滞信号触发 seed generation boost；仍不是完整多目标资源闭环 |
| Seed-Gen: `SEED_INIT` | 已还原 | `apps/workers/seed/main.py` `seed/seed_manifest.json` | source-side主路径已通 |
| Seed-Gen: `VULN_DISCOVERY` | 未还原 | 无正式 worker/manifest | 目前只有 placeholder 概念 |
| Seed-Gen: `SEED_EXPLORE` | 未还原 | 无正式 worker/manifest | 目前未实现探索任务 |
| 探索/利用预算分配 | 未还原 | 无独立 selector/budgeting 逻辑 | 当前未形成 Buttercup 原式 budget 分配 |
| duration / deadline 持续运行语义 | 部分还原 | `apps/workers/campaign/main.py` `core/campaign/*` | duration/deadline 已有；但长期调度和反馈回注仍偏轻量 |
| fuzz / corpus / dedup / trace / repro / PoV | 已还原 | `apps/workers/fuzzer/main.py` `apps/workers/tracer/main.py` `apps/workers/reproducer/main.py` | source-side strict-live 已闭环 |
| patcher 多智能体链路 | 未还原 | patch reserved only | 目前只是 API/status/目录占位 |
| binary 作为并列输入入口 | 部分还原 | `adapter_resolution=binary` `apps/workers/binary_analysis/main.py` `apps/workers/binary_seed/main.py` | analysis 已成活；binary-native seed 本轮开始接入；仍未完全摆脱 source-derived execution semantics |
| binary-native AI seed generation | 部分还原 | `core/binary_seed/*` `apps/workers/binary_seed/main.py` | 本轮开始基于 ida_mcp 输出生成真实 `.seed` |
| binary-side context retrieval / slicing | 部分还原 | `core/binary_seed/context_retriever.py` `core/binary_seed/slicer.py` | 当前是工程务实版 slice，不是完整静态切片 |
| harness / target / resource weighting | 伪还原 | `core/seed/harness_selector.py` | 目前主要是单目标优先级选择，不是 Buttercup 级资源权重系统 |
| campaign 级调度与资源控制 | 部分还原 | `core/campaign/*` `runtime/campaign_manifest.json` | duration/campaign 已有，但 coverage/budget/seed strategy 反馈仍不完整 |

## Campaign Manifest 语义说明

- `total_raw_crash_count` / `total_traced_crash_count` 表示跨 round 汇总后的累计 crash 观测值，不再使用 `new_*` 误导成“新增量”。
- `distinct_pov_count` / `distinct_signature_count` 表示跨 round 去重后的 PoV 文件名和 crash 签名数量。

## 主架构 vs benchmark 适配

### 主架构

- `task -> scheduler/planning -> program-model/build -> seed -> fuzz/binary execution -> trace -> repro -> PoV`
- queue / state / runtime manifest / campaign inventory / vuln attribution
- source-side 与 binary-side 共用 tracer / reproducer / reporting 主链

### benchmark-specific adapter

- `cjson_read_fuzzer`
- `fuzz_main.c`
- `glibc239_binary_launcher.sh`
- `source_derived_binary`
- `benchmarks/cjson_injected/*`

这些属于 **benchmark-specific adapter / execution binding**，不是 Buttercup-lite 主架构本体。

## 当前必须承认的关键缺口

1. **coverage feedback 还只是最小可用闭环，不是完整 Buttercup 反馈系统**
2. **Seed-Gen 仍然缺少 `VULN_DISCOVERY` / `SEED_EXPLORE` 任务家族**
3. **binary 还没有完全成为与 source 完全对等、完全独立语义的入口**
4. **patcher 多智能体链路仍然只是 placeholder**
