# buttercup-lite 代码归档说明

## 1. 系统概况

- 项目名称：`buttercup-lite`
- 项目用途：这是对 Trail of Bits Buttercup 的轻量化重构版本，当前定位为一个 Compose-first 的前半链路系统，覆盖 source lane、generalized source lane 和 binary lane 的任务编排、构建、seed、fuzz、trace、repro 与 PoV 前置链路。
- 架构概述：核心工作流为“任务接入 -> 标准化 -> 索引 -> 构建 -> seed -> fuzz -> crash -> trace -> repro -> pov”。当前以 Docker Compose 统一拉起 15 个 service，具体包括 `redis`、`api-server`、`downloader-worker`、`scheduler-worker`、`binary-analysis-worker`、`binary-execution-worker`、`binary-seed-worker`、`builder-worker`、`seed-worker`、`fuzzer-worker`、`tracer-worker`、`reproducer-worker`、`protocol-execution-worker`、`patch-worker`、`program-model-worker`。
- 核心组件：
  - `campaign daemon`：驱动单个 campaign 的 build/seed/fuzz/trace/repro 循环。
  - `fuzzer worker`：负责 libFuzzer 执行、coverage/crash 产物回收、reseed 触发。
  - `seed worker`：负责 LLM seed 生成、多 batch target function 选择与导入 seed 策略。
  - `tracer`：负责 trace admission、trace replay 与 trace artifact 产出。
  - `reproducer`：负责复现、repro 尝试与 PoV 前置确认。
  - `binary analysis`：负责 IDA facts、函数签名、call graph、imports/type 信息抽取。
  - `coverage plane`：负责 exact/partial coverage、coverage queue、uncovered/low-growth/stalled target 反馈。
  - `corpus merger`：负责 shared corpus export/import、跨 lane corpus economy 和 quality gate。
  - `slot controller`：负责长时间 proof/overnight 的 slot continuity、warm-up、continuation/replacement 调度。
  - `family confirmation`：负责 exact signature、loose cluster、confirmed family 三层 crash family 语义。
- LLM 配置：
  - `model=deepseek-chat`
  - `base_url=https://api.deepseek.com`
- 服务器信息：
  - `server=222.20.126.154`
  - `repo_path=/home/buttercup2/Project/buttercup-lite`

## 2. 压缩包内容（已保留）

- `apps/`
  - 用途：worker 服务入口层。
  - 核心内容：`apps/api_server/main.py`，以及 `apps/workers/*/main.py`，包括 `seed/fuzzer/tracer/reproducer/binary_analysis/binary_execution/binary_seed/builder/program_model/protocol_execution/patch/campaign` 等入口。
  - 作用：定义各 compose service 的实际启动点，是整个系统的进程入口。
- `core/`
  - 用途：核心业务逻辑。
  - 核心内容：`core/campaign`、`core/analysis`、`core/coverage`、`core/seed`、`core/binary`、`core/program_model`、`core/tracer`、`core/reproducer`、`core/planning`、`core/patch_plane` 等模块。
  - 作用：承载任务状态机、coverage plane、binary lane、family confirmation、corpus merger、slot controller 等主逻辑。
- `config/`
  - 用途：系统配置和契约定义。
  - 核心内容：`build_contracts.py`、`dataset_contracts.py` 等。
  - 作用：约束数据集和构建相关输入输出格式，便于在 worker 之间共享一致配置。
- `deploy/`
  - 用途：部署补充文件。
  - 核心内容：`deploy/Dockerfile`。
  - 作用：定义 compose 服务共用镜像的构建方式。
- `scripts/`
  - 用途：运维、启动、验证与阶段性 proof 辅助脚本。
  - 核心内容：`run_*`、`validate_*`、`submit_*`、`verify_*` 脚本，以及 `ida_mcp_bridge.py`。
  - 作用：支持快速复现实验、提交流水线、做阶段性验证和本地自动化。
- `tests/`
  - 用途：测试用例。
  - 核心内容：当前主要包含 `test_program_model_phase2.py`、`test_protocol_backend.py`。
  - 作用：为 program model 和 protocol backend 提供基础回归测试。
- `tooling/`
  - 用途：开发工具和工具链说明。
  - 核心内容：`build_toolchain.environment.yml`。
  - 作用：记录构建环境/工具链依赖，便于重建本地或容器环境。
- `adapters/`
  - 用途：适配层目录。
  - 核心内容：用于承接 benchmark/任务接入适配逻辑的仓位目录。
  - 作用：为后续 benchmark 接入、协议适配与 source/binary 输入标准化留出清晰边界。
- `docs/`
  - 用途：项目文档。
  - 核心内容：`architecture_alignment.md`、`buttercup_mechanism_audit.md`、`fuzz_validation_criteria.md`、`original_buttercup_dependency_closure.md`、`pure_binary_definition.md`。
  - 作用：记录系统设计、与原 Buttercup 的对齐情况、binary 机制和验证标准。
- `reports/`
  - 用途：阶段性审计、proof 与最终验收报告归档目录。
  - 核心内容：`final_integration_proof.json`、各轮 `disk_cleanup_*`、`root_alignment_*`、prompt proof/audit/verdict 报告。
  - 作用：为老师审阅代码演进、阶段性验证和最终整合验收提供配套证据。
- `benchmarks/`
  - 用途：基准任务定义与小型 fixture。
  - 核心内容：`benchmark.json`、`ground_truth.json`、`seed_fixtures.py`，涉及 `cjson_injected`、`expat_source`、`h3_source`、`inih_injected`、`binary_imported`、`libxml2` 等。
  - 作用：提供任务元数据、基准入口与小型对照信息。
  - 说明：本目录原始大小只有 `140K`，不属于大体积 benchmark 源码/预编译 binary，因此本次归档保留。
- `offline_eval/`
  - 用途：离线评估目录。
  - 核心内容：局部评估脚本、轻量数据与不依赖完整线上链路的验证材料。
  - 作用：帮助在不启动完整 worker 集群时做离线分析和对比。
- `docker-compose.yml`
  - 用途：定义全部 15 个 compose service。
  - 核心内容：worker 拓扑、环境变量、卷挂载、镜像构建、依赖顺序。
  - 作用：是一键拉起系统的主部署入口。
- `Makefile`
  - 用途：构建、启动、日志查看、提交任务、测试的统一入口。
  - 核心内容：`up/down/logs/submit/test` 等命令。
  - 作用：简化本地和服务器上的常用运维操作。
- `requirements.txt`
  - 用途：Python 依赖清单。
  - 核心内容：`fastapi`、`uvicorn`、`redis`、`pydantic`、`tree-sitter`、`tree-sitter-language-pack` 等。
  - 作用：支持 API 服务、worker 和源码索引/解析能力。
- `.env`
  - 用途：当前服务器上的真实运行环境变量文件。
  - 核心内容：DeepSeek API、数据路径、fuzz/build/campaign 参数等本地运行配置。
  - 作用：方便老师直接复现当前环境配置。
  - 提醒：该文件可能包含明文 `LLM_API_KEY`，需要在对外发送前人工清理。
- `.env.example`
  - 用途：环境变量模板。
  - 核心内容：DeepSeek API、路径配置、fuzz/build/campaign 参数。
  - 作用：指导在新环境中创建可运行的 `.env`。
- `README.md`
  - 用途：项目主说明。
  - 核心内容：quick start、任务接入 contract、任务查看方式。
  - 作用：帮助审阅者快速理解项目的启动方式和任务接口。
- `ARCHIVE_README.md`
  - 用途：本次归档专用说明文档。
  - 核心内容：保留/排除说明、修复清单、遗留问题、运行方式。
  - 作用：让老师在不恢复完整运行时数据的情况下也能快速理解代码包内容。
- `reports/` 中的 `root_alignment_*.json`、`disk_cleanup_*.json`
  - 用途：阶段性对齐、proof 和磁盘清理的补充审计材料。
  - 核心内容：阶段性 audit、plan、verdict、proof report。
  - 作用：提供开发过程的验收痕迹，便于老师对照演进过程。

## 3. 已排除内容

说明：以下目录/文件在归档说明中保留语义说明，但在本次 `tar.gz` 中按内容整体排除，不随源码一起打包。

### data/
原始大小：`70G`

内容说明：运行时产物根目录，包含 `data/tasks`（每个 campaign/fuzz/trace/repro 任务的工作目录，含 `corpus/active`、`crashes/raw`、`coverage/profraw`、build 产物、源码副本等）以及 `data/datasets`（benchmark 数据集）。

排除原因：纯运行时产物，体积极大，不含核心源码逻辑。

### runtime/
原始大小：`136M`

内容说明：slot controller 运行时状态、`proof_runs`（各次 proof 的 `stdout.log`、manifest、summary）、`long_runs` 等目录。

排除原因：纯运行时日志和状态文件，不含核心源码。

### ida_pro/
原始大小：`843M`

内容说明：IDA Pro 相关工具和脚本，用于 binary 分析时提取函数签名、call graph、type info 等 IDA facts，供 binary lane 使用。

排除原因：体积较大，且本质上是第三方二进制工具，不是项目源码。

### .toolchains/
原始大小：`1.9G`

内容说明：LLVM/Clang 工具链，包含 `llvm-profdata`、`llvm-cov`、`clang++`、`llvm-symbolizer` 等，用于 coverage 采集和 crash symbolization。

排除原因：二进制工具链，可通过 Dockerfile 或环境脚本重新安装。

### .venv/
原始大小：`63M`

内容说明：Python 虚拟环境，保存所有 Python 依赖安装结果。

排除原因：可通过 `pip install -r requirements.txt` 重建，不需要随源码打包。

### .codex/
原始大小：`8.0K`

内容说明：本地 AI 辅助开发工作目录，存放 Codex/Claude 类工具的会话辅助痕迹。

排除原因：开发辅助文件，不属于项目源码。

### benchmarks/
原始大小：`140K`

内容说明：主要是 benchmark 元数据、ground truth 和小型 seed fixture，不是大体积 benchmark 源码或预编译 binary。

处理结论：本次未排除，已保留进压缩包，因为体积很小且对理解系统测试入口有帮助。

## 4. 已完成的关键修复清单

- [P1] `core/analysis/suspicious_candidate.py`：generalized candidate 的优先级改为 stderr/ASAN/UBSAN/timeout 优先，并限制低质量 `corpus_growth` claim。
- [P2-1] `core/campaign/coverage_queue.py`：建立 durable coverage queue，让 uncovered/low-growth/stalled target 能跨 continuation 持续存在。
- [P2-2] `apps/workers/seed/main.py`：seed 规划开始把 coverage queue 当作 first-class input 消费，而不只是 prompt hint。
- [P7] `core/analysis/family_confirmation.py`：让 loose cluster 真正进入 conservative split/merge 与 confirmed family 决策链。
- [P9-1] `core/campaign/executor.py`：修复 round clone 时丢失 coverage 输出路径的问题，恢复 source lane `.profraw` 产出。
- [P9-2] `core/coverage/llvm_source.py`：修复 coverage binary 查找链的 path canonicalization，避免 generalized lane 因路径 miss 退化为 fallback。
- [P3] `core/binary/feedback_bridge.py`：下调 informational -> promotion 门槛，并让 binary strong signal 能接入统一 candidate/trace 主链。
- [P4-1] `core/campaign/corpus_merger.py`：把 shared corpus export/import 和 quality gate 变成真实的跨 lane workflow，而不是仅写统计。
- [P4-2] `core/campaign/runtime_state.py`：generalized lane 在没有 raw crash 时，只要有 coverage growth 或 corpus growth 也能触发 export。
- [P5-1] `core/campaign/slot_controller.py`：加入 warm-up 预启动与更短轮询周期，缩短 overnight slot 切换空窗。
- [P5-2] `core/campaign/slot_controller.py`：在 manifest 安全落盘后异步 teardown 旧 child，不再串行等待旧进程完全退出再放行新 child。
- [P4-3] `core/campaign/runtime_state.py`：修复 generalized export guard，在 `new_corpus_files` 为空时改用 `round_local_growth_hint` 回收 `corpus/active`。
- [P8-1] `apps/workers/seed/main.py`：multi-batch 策略改为函数多样化，分别覆盖 coverage queue top-1、top-2、family stagnation 和 open-ended exploration。
- [P8-2] `apps/workers/seed/main.py`：增加跨轮 `recently_used_targets` rotation，优先跳过最近刚用过的 target function。

## 5. 已知遗留问题

### 机制存在但未完全达标

- exploration depth 已有多 batch 和 coverage queue 驱动，但 5 小时最终 proof 中 `source unique_target_functions_per_hour=4.6`、`generalized=2.8`，仍低于目标值。
- overnight continuity 已有 warm-up 和异步 teardown，但 5 小时最终 proof 中 `idle_gap_total_seconds=656.789`、`wall_clock_utilization_ratio=0.9687`，仍未完全达标。
- generalized lane 的 trace 链路已经通，但 expat 的 `no_actionable_signal` 比例仍高，说明信号质量问题尚未被彻底缓解。

### 机制代码存在但从未 live 命中

- harness rebinding 代码路径存在，但最终 proof 中 `generalized_harness_switch_count=0`，尚未 live 命中。
- family reconfirmation 分支代码存在，但最终 proof 中 `requires_reconfirmation_hits=0`。
- conservative split guard 代码存在，但最终 proof 中 `conservative_split_guard_hits=0`。

### 架构级遗留待方向确认（A-01 至 A-08）

- `A-01`：patch synthesis 仍依赖 `known_fix` 风格模板，尚未完全变成强通用补丁综合。
- `A-02`：program model 仍偏静态 snapshot，而不是贯穿整个 campaign 的持续自刷新模型。
- `A-03`：seed 生成目前仍是单次 prompt per batch，不是多轮 seed refinement。
- `A-04`：在最终整合报告中未再被单列为主残留，视为已被前序 workflow 修复吸收，但仍建议在后续工作中复核是否完全收敛。
- `A-05`：在最终整合报告中未再被单列为主残留，视为已被前序 workflow 修复吸收，但仍建议在后续工作中复核是否完全收敛。
- `A-06`：在最终整合报告中未再被单列为主残留，视为已被前序 workflow 修复吸收，但仍建议在后续工作中复核是否完全收敛。
- `A-07`：patch reflection 仍可能消耗重试次数，但没有产生足够新的语义推理。
- `A-08`：QE gate 仍不完整，距离完全自治 repair closure loop 还有差距。

## 6. 如何在新环境运行

1. 环境要求
   - Linux x86_64 服务器或工作站
   - Docker 与 Docker Compose
   - Python 3.10+
   - 可访问 `https://api.deepseek.com`
   - 如需 binary lane 的完整能力，额外准备 LLVM 工具链和可选的 IDA 环境

2. 配置 `.env`
   - 复制 `.env.example` 为新的本地 `.env`
   - 至少设置 `LLM_API_KEY`、`LLM_BASE_URL=https://api.deepseek.com`、`LLM_MODEL=deepseek-chat`
   - 按新机器修改 `HOST_HOME`、`DATA_ROOT`、`BUILD_TOOLCHAIN_PREFIX` 等路径

3. 启动 compose 服务
   - 在项目根目录执行 `make up`
   - 或执行 `docker compose up -d --build`

4. 启动 campaign daemon
   - 常规方式：先通过 API 提交任务，随后由 `scheduler-worker` 把任务推进到 `campaign` 阶段，`apps/workers/campaign/main.py` 会自动接管运行
   - 手工方式：对已有任务设置 `CAMPAIGN_TASK_ID=<task_id>` 后执行 `python -m apps.workers.campaign.main`
   - 任务提交后，可通过 `curl http://127.0.0.1:8000/tasks/<task_id>` 或查看 `data/tasks/<task_id>/task.json` 观察状态推进
