# Fuzz Validation Criteria

## 结论先行

需要明确区分两件事：

- `single strict-live proof`
- `sustained fuzz validation`

我们此前已经完成前者。
本轮开始补后者。

## 1. Single strict-live proof

### source-side

满足以下条件即可算单轮 strict-live：

- selected harness 固定
- live fuzz 真实启动
- 产生 live raw crash
- tracer 获得 `trace_mode=live_asan`
- repro 稳定
- 产出 PoV
- `closure_mode=strict_live`

### binary-side

满足以下条件即可算单轮 strict-live：

- `target_mode=binary`
- `binary_provenance=source_derived_binary`
- binary analysis 已完成
- binary execution plan 已完成
- live binary crash candidate 产生
- binary trace / repro / PoV 打通
- `closure_mode=strict_live`

## 2. Sustained fuzz validation

### source-side 必须满足

- campaign 模式，不是单轮任务
- 至少 `campaign_rounds >= 5` 或总时长 >= 30min
- 每轮保留：
  - corpus before/after
  - new crash count
  - new traced crash count
  - new PoV count
  - new distinct signature count
  - cumulative distinct signature count
- `pov_inventory.json` 存在
- `vuln_coverage.json` 存在
- 能回答：
  - 已发现几个注洞
  - 未发现几个注洞

### binary-side 必须满足

- binary campaign 模式，不是单次 binary execution
- 至少 `campaign_rounds >= 5` 或总时长 >= 30min
- 每轮保留：
  - binary crash candidate count
  - traced binary crash count
  - binary PoV count
  - new distinct signature count
  - cumulative distinct signature count
- `target_mode=binary`
- `binary_provenance=source_derived_binary`
- `pov_inventory.json` 存在
- `vuln_coverage.json` 存在

## 3. 当前阶段判断标准

### source-side

- 单轮 strict-live：已完成
- sustained fuzz validation：本轮以 `campaign_rounds=5` 为最小验收

### binary-side

- 单轮 strict-live：已完成
- sustained fuzz validation：本轮以 `campaign_rounds=5` 为最小验收

## 4. 结果解释原则

如果 sustained campaign 已跑完，但 distinct PoV 仍然不多，不能直接判系统无效。

需要先看：

- harness 覆盖是否偏窄
- seed 多样性是否不足
- 运行时长是否仍偏短
- ground truth 归因是否有不确定项
- binary path 是否仍受 source-derived semantics 约束

