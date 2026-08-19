# Cross-Layer Vulnerability Semantics

## 正式定义

ChipChain 的跨层安全关联是：在同一芯片架构体系内，一个层级中的漏洞、程序行为或
异常硬件状态，通过指令执行、数据流、控制流、寄存器/MMIO、DMA、中断、权限状态、
共享内存或其他真实软硬件接口传播至另一层级，触发、放大或传播安全弱点并产生影响。

统一对象不是只有 Vulnerability→Vulnerability，而是：

```text
Vulnerability / Behavior / Fault State
  → Cross-Layer Interaction
  → Vulnerability / Behavior / Fault State
  → Security Impact
```

跨层始终发生在同一 architecture 内；统一分析框架不等于统一底层架构语义。

## Type I：Firmware Vulnerability to Hardware

```text
software-side vulnerability
  → attacker-controlled instruction / MMIO behavior
  → hardware-side vulnerability
```

必须显式引用两侧不同的 vulnerability 和 trigger behavior。方向固定为
software_to_hardware。模型描述 scenario/hypothesis，不声称漏洞已经验证。

## Type II：Firmware Behavior to Hardware

```text
normal software-side behavior
  → specific instruction / MMIO sequence
  → hardware-side vulnerability
```

initiating vulnerability 必须为空。正常代码不能为数据结构方便被伪造成 firmware
vulnerability。方向固定为 software_to_hardware。

## Type III：Hardware Vulnerability to Firmware

```text
hardware-side vulnerability
  → fault / interrupt / DMA / returned or corrupted state
  → software-side execution affected
```

必须包含 initiating hardware vulnerability 和 affected execution；target firmware
vulnerability 可以为空。方向固定为 hardware_to_software。Phase 8R 仅提供数据契约，
没有反向 Search、分析器或 synthetic BehaviorEdge。

## Layer 与 Direction

类型名中的 firmware-side 泛指当前 `firmware`、`driver`、`interface` 软件执行侧；
hardware-side 为 `hardware`。没有真实用例前不扩展 OS/application。

InteractionType 唯一决定 Direction，非法组合由模型拒绝。类型必须来自 dataset
annotation、explicit input 或 deterministic classifier；Qwen/Multi-Agent 不得自由分类。

## 三种位置语义

```text
initiating_root_cause
  → cross_layer_trigger_point
  → affected_execution_point
```

- Initiating Root Cause：漏洞/异常真正起因；
- Cross-Layer Trigger Point：跨层传播发生的指令、接口、寄存器访问或硬件状态；
- Affected Execution Point：另一层受到影响的位置。

Type II 的 MMIO instruction 通常只是 trigger point。Type III 的 hardware vulnerability
可为 initiating root cause，而 firmware branch/function 是 affected execution point。
历史 `RootCause` 不在本阶段重命名。

## 与现有 Pipeline 的关系

Phase 6 `CrossGraphCandidate` 保持 software→hardware exact-anchor primitive。它可能为
Type I/II 提供底层候选，但无法区分软件行为是否源于软件漏洞；它不能自动分类，也不
支持 Type III。Phase 7/8 仍只解释这个 legacy primitive。

`VulnerabilitySample` 继续表示原子漏洞知识；`CrossLayerInteraction` 独立引用漏洞、
行为、fault state 和资源，不写回 Behavior Graph 或 Knowledge Graph。

