# Root-Cause Localization MVP

## 结果语义

Phase 9A 输出 `RootCauseLocalizationResult`，它是 security-relevant sink candidate，
不是 `Root Cause Verified`。Knowledge RootCause 是 prior hint，必须与程序事实比较，
不能直接复制为定位结果。

## 确定性算法

1. 从 Candidate Behavior Path 找到 verified MMIO_READ/MMIO_WRITE Edge；
2. 从该 Edge 自己的非 LLM Static Evidence 提取 instruction address；
3. 从 source Function 提取 function ID/name 与 binary start address；
4. 从 Hardware endpoint 提取 MMIO address；
5. 比较 KG hint 的 function、binary address、instruction、MMIO address 和 resource；
6. 一致项提供上下文支持，明确不一致写入 `contradictions`。

状态只允许 `localized_candidate`、`insufficient_evidence` 和
`contradictory_context`，第一版没有 `verified`。

## 地址语义

`ProgramAddress` 用于 function/binary/instruction namespace，`HardwareAddress` 用于
MMIO/resource namespace。当前 fixture 中：

```text
function start       0x10000  ProgramAddress
MMIO sink instruction 0x10008 ProgramAddress
MMIO register        0x40000000 HardwareAddress
```

KG RootCause Evidence 的 `address=0x40000000` 是 hardware/MMIO 地址，不能当作程序
指令位置。`source_file` / `source_line` 只有在 Evidence 显式给出时才填写；binary byte
或 instruction distance 不等于 source-line error。

## 隔离与后续

LLM recommendation、SemanticHypothesis 和 Critic text 不进入 supporting Evidence。
Phase 9B 可用授权动态 trace 增加观察证据；Phase 10 在具有 source-line Ground Truth 的
冻结数据集上评测定位误差。
