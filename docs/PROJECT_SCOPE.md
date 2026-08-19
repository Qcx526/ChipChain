# 项目范围

## 项目定义

ChipChain（Evidence-Guided LLM Collaboration for Cross-Layer Chip Vulnerability Chain Detection）是一个防御性科研系统。它关联同一芯片架构内的软件漏洞、正常程序行为、
硬件漏洞或异常状态、真实层间接口及安全影响。

系统关注的问题不是描述是否相似，而是安全状态能否沿真实指令执行、数据流、控制流、
MMIO/寄存器、DMA、中断、权限状态或共享内存传播到另一层，触发、放大或传播安全弱点。

## “跨层”的定义

正式 Cross-Layer Semantics 包含三类：

```text
Type I   firmware-side vulnerability → cross-layer behavior → hardware vulnerability
Type II  normal firmware-side behavior → cross-layer trigger → hardware vulnerability
Type III hardware vulnerability/fault → propagation → firmware-side execution affected
```

因此漏洞不是所有跨层链的必需起点。这里 `firmware-side` 泛指当前已有的 firmware、
driver、interface 软件执行侧。Type II 不得伪造软件漏洞；Type III 不得把既有路径反转
当作证据。有效关联最终必须由知识图、程序/运行证据或架构规则支持。

## “非跨架构”的定义

研究对象是单一架构内部的纵向跨层关系。ARM 固件、ARM 驱动、ARM 特权接口和 ARM 硬件安全机制可以组成一条链；ARM、RISC-V、PowerPC 等架构的专有节点不得拼接成同一条链。

当前阶段只建设 ARM MVP。未来不同架构共享上层分析框架，但 Adapter、Rules、Knowledge
和底层传播机制保持隔离，即“统一分析框架，不统一底层架构语义”。

## 研究目标

- 标准化固件和硬件漏洞输入。
- 建模漏洞知识图谱与跨层行为图。
- 在架构约束下搜索候选攻击路径。
- 用知识检索辅助语义推理，但不让 LLM 替代程序分析。
- 逐边验证程序行为、接口、权限和硬件交互证据。
- 计算可配置、可消融的链置信度和证据覆盖率。
- 定位到函数、地址、指令、寄存器、资源或安全机制等根因。
- 输出机器可读 JSON 与面向研究人员的可解释报告。

## 系统输入

- 上游漏洞检测结果：位置、类型、CVE/CWE/CAPEC、触发条件、影响和来源。
- 目标固件或其静态分析结果：函数、调用图、CFG、数据流、污点、系统调用、ioctl、MMIO 和寄存器访问。
- 可选动态证据：执行、函数、系统调用、MMIO 和寄存器 trace。
- 目标架构及其权限、地址范围、寄存器、资源所有权和安全机制规则。
- 具有可信来源的漏洞知识和结构化 Ground Truth。

## 系统输出

- 按置信度排序的候选或已验证攻击链。
- 每条链的架构、入口、节点、边、逐边证据、证据覆盖率和最终影响。
- 验证状态、未满足条件和置信度组成。
- 函数、二进制地址、指令、MMIO 地址、寄存器和硬件资源等根因位置。
- JSON 结果、可解释文本和评测报告。

## 硬指标与阶段化解释

- 最终框架目标支持不少于 5 种嵌入式架构：ARM、RISC-V、PowerPC、SPARC、LoongArch。
- 最终关联漏洞命中率目标不低于 80%，必须用固定 Benchmark 和明确指标验证。
- 最终漏洞样本库不少于 100 条，并保留真实样本来源；第一阶段只准备 10–20 条高质量 ARM 样本。
- 当前首要目标是完成 ARM 的 `Firmware Function → Driver/ioctl → MMIO → Register → Hardware Resource` 可运行闭环。

这些是研究路线指标，不代表 Phase 0 已实现或已达到。

## 非目标

- 跨架构统一指令语义或跨架构攻击链拼接。
- 针对未授权真实系统的武器化 exploit。
- 在没有程序证据的情况下让 LLM 直接分析固件并宣称发现真实链。
- 第一版同时接入五种架构、多个分析平台或生产级图数据库。
