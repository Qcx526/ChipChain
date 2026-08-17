# angr 接入计划（Planned / Not Implemented）

## 状态与边界

本文只记录 Phase 3 完成后的可行性计划。仓库当前没有 `angr` 依赖、`AngrAnalyzer` 类或真实二进制分析实现。正式接入必须由后续任务明确授权，并保持 `ProgramAnalyzer → ProgramAnalysisResult` 契约不变。

angr 只负责从授权二进制中恢复可观察程序事实，不负责输出 CVE、CWE、Hardware Weakness、Exploitability、Privilege Escalation、Verified AttackChain 或其他安全结论。

## 1. angr 将负责什么

第一版 AngrAnalyzer 计划只负责：

- 装载目标程序及其架构/地址布局；
- 恢复函数地址、名称或稳定的合成符号；
- 恢复直接调用和可解析的间接调用；
- 保存调用点地址并生成 CALLS Evidence；
- 检查明确可解析的内存访问，结合已知设备内存映射产生 MMIO_READ/MMIO_WRITE 观察；
- 把结果转换为现有 BehaviorNode、BehaviorEdge 和 Evidence。

不在第一版范围内：完整污点分析、漏洞检测、固件解包、动态执行、硬件弱点推断或攻击链生成。

## 2. 输入范围

建议按以下顺序逐步支持：

1. 带明确架构和装载信息的 ARM ELF；
2. 静态链接或依赖可控的 ELF；
3. 已知 base address、entry point 和 ARM/Thumb 模式的 raw binary；
4. 已从 firmware image 中提取的独立可执行 payload。

Firmware unpacking 不属于 AngrAnalyzer。raw binary 缺少段、符号和装载地址，必须通过 ProgramArtifact metadata 或单独配置提供，不应猜测成事实。

官方文档说明 angr 的 CLE loader 负责把不同二进制对象映射到统一地址空间；实际实现前仍需针对选定 angr 版本验证具体 loader 参数：[Loading a Binary](https://docs.angr.io/en/stable/core-concepts/loading.html)。

## 3. Function 提取

第一版优先使用静态 CFG 恢复函数边界和 FunctionManager 信息。官方资料将 CFGFast 描述为更快、依赖启发式和假设的静态恢复，而 CFGEmulated 使用符号执行、成本显著更高：[CFGFast API](https://docs.angr.io/en/latest/api/angr.analyses.cfg.cfg_fast.html)、[CFG Recovery](https://docs.angr.io/en/v9.2.63/analyses/cfg.html)。

因此计划：

- 默认从 CFGFast 获取函数地址、名称、区间和调用关系；
- 对 stripped binary 使用 `sub_<address>` 等稳定合成名称；
- 保留 recovered / symbol-backed 等 provenance metadata；
- 不把“函数未恢复”解释为“函数不存在”；
- CFGEmulated 只用于小范围、有边界的补充实验，不能成为默认全固件路径。

## 4. Call Graph 与 CALLS Evidence

AngrAnalyzer 应把调用者/被调用者转换为 Function 或 DriverFunction BehaviorNode，把调用转换为 RelationType.CALLS。

每条 CALLS Edge 至少引用一条 Evidence：

- `type=static_analysis`；
- `source=angr_analyzer`；
- `artifact=ProgramArtifact.id`；
- `address=call-site instruction address`；
- `instruction=反汇编或规范化 IR 摘要`；
- metadata 保存 caller/callee address、direct/indirect 和解析状态。

未解析的间接调用不得伪造 callee。可保留诊断统计，但不生成指向猜测目标的已确定 CALLS Edge。

## 5. Function XRef

第一版不新增 XREF RelationType。函数 XRef 仍表示为：

```text
CALLS Edge
    → evidence_ids
    → call-site Static Evidence
```

这与 DemoAnalyzer 契约一致，避免将 angr 专有对象泄漏到公共模型。

## 6. MMIO 第一版识别计划

真实 ARM 指令：

```text
STR X0, [X1]
```

只能说明存在内存写。只有解析出 X1 最终落入目标设备已知 MMIO range，才能生成 MMIO_WRITE。

第一版计划组合：

1. 从指令或 VEX IR 找出 load/store 地址表达式；
2. 对常量、PC-relative、基址加常量偏移做有限 constant propagation；
3. 将已解析地址与用户提供的 architecture/device memory map 匹配；
4. 保存 instruction address、resolved target、range/rule ID 和解析方法；
5. 地址仍为 symbolic 或区间不确定时，不生成确定 MMIO Edge，只记录 unresolved diagnostic；
6. 对同一地址的 READ/WRITE 使用现有 MMIO_READ/MMIO_WRITE RelationType。

必须明确：

```text
Demo fixture MMIO recognition != 真实 ARM MMIO recognition
```

DemoAnalyzer 读取 fixture 中明确给出的地址；真实实现需要 constant propagation、address resolution、known MMIO ranges、symbolic address handling 和设备 memory map。

## 7. 转换到 ProgramAnalysisResult

计划中的 AngrAnalyzer 仍只返回：

```text
ProgramArtifact
architecture
BehaviorNode[]
BehaviorEdge[]
Evidence[]
metadata
```

转换流程：

```text
angr/CLE/CFG internal objects
        ↓ adapter-only normalization
BehaviorNode / BehaviorEdge / Evidence
        ↓
ProgramAnalysisResult validation
```

Node、Edge、Evidence ID 必须确定性生成并排序；不得把 angr NetworkX 图、CFGNode、Function 或 SimState 暴露给上层。随后继续复用 `ingest_analysis_result` 写入 GraphRepository。

## 8. 已知技术风险

- stripped binary 的函数边界和名称不完整；
- ARM/Thumb 模式和跳转地址低位语义；
- 间接调用、跳转表、tail call 和异常控制流恢复不完整；
- PIE、重定位、外部库和装载基址导致地址不稳定；
- raw binary 缺少段权限、符号和入口信息；
- CFGFast 启发式可能产生漏报或误报；
- CFGEmulated 可能出现状态爆炸和高内存消耗；
- symbolic address 无法可靠归入一个 MMIO range；
- 错误或不完整的设备 memory map 会直接影响 MMIO 结论；
- angr、Python 版本和本地原生依赖兼容性需要单独验证；
- 大型固件需要超时、区域白名单、函数预算和缓存策略。

## 9. 实施前验证门槛

正式编码前应先固定：

- 一个自有 ARM ELF toy program；
- 明确的符号、调用点和 MMIO range Ground Truth；
- 支持的 angr/Python 版本矩阵；
- 函数、CALLS、call-site 和 MMIO 的接受标准；
- 超时、最大函数数和最大 CFG 节点数；
- 与 DemoAnalyzer 生成相同 ProgramAnalysisResult 语义的对照测试。

只有这些门槛明确后，才适合增加可选 `angr` dependency group 和 AngrAnalyzer。本 Phase 不执行安装或实现。
