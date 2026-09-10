# V2 科学边界

以下区分适用于全部后续合同、实现、测试和实验报告：

- Decoded Instruction != Executed Instruction
- Static Path != Runtime Path
- CFG Reachability != Runtime Reachability
- Instruction Presence != Hardware Trigger
- Code Similarity != Trigger Equivalence
- Program Order != Runtime Timing
- Processor Behavior Fact != Vulnerability
- Trigger Match Candidate != Verified Vulnerability
- LLM Claim != Objective Evidence
- Modified Firmware != Evidence For Original Firmware
- Different Firmware SHA != Same Target
- Different Firmware SHA != Same Firmware Target
- JTAG Observation != JTAG State Injection
- JTAG Observation != Firmware Modification
- Injected State != Naturally Reached State
- Synthetic Fixture != Client-Target Evidence
- Architecture Vocabulary != Production Backend Support
- Artifact Provenance != Evidence Truth
- Artifact SHA != Vulnerability Verdict
- Address != Execution
- Address != MMIO
- Address != Memory Access
- Same Architecture != Same Hardware Target
- Same Model String != Verified Revision Equality
- ProcessorFuzz Target != Automatically Client Hardware Target
- Target Identity != Hardware Applicability Verdict
- Declared Firmware SHA != Verified File Bytes
- ProcessorFuzz Artifact != Hardware Trigger IR
- ProcessorFuzz Artifact != Client Hardware Applicability
- Hardware-Team Valid SI != ChipChain Verified Hardware Vulnerability
- External Team Confirmation != ChipChain Verification
- SI Testcase != Hardware Trigger Specification
- Whole SI != Minimal Trigger
- ISA Trace != Physical Silicon Trace
- RTL Simulation != Physical Silicon
- ISA/RTL Difference != Automatically Vulnerability
- ISA/RTL Signature Difference != Automatically Root Cause
- Disassembly != Runtime Execution
- ELF/HEX != Original SI Semantics Automatically
- ProcessorFuzz Hardware Target != Client Hardware Target
- Same RISC-V != Same Hardware Target
- Rocket Model Known != Exact Rocket Configuration Known
- ProcessorFuzz Tool Known != ProcessorFuzz Version/Profile Known
- Partial Declared Provenance != Authenticated Provenance
- Source Text Instruction != Decoded Machine Instruction
- Register Operand != Register Access
- Data Token != Addressed Memory State
- Data Ordering != Memory Address
- Partial Projection != Parser Failure
- SI Presence != Firmware Reachability
- GDBFuzz Artifact != Firmware Vulnerability
- Coverage != Runtime Path Proof
- Crash != Cross-Layer Vulnerability
- Testcase != Trigger
- Adapt Host Input Delivery != Modify Firmware
- Custom Host Adapter != Firmware Instrumentation
- Input Delivery Provenance != Firmware Behavior
- Host Adapter != Firmware Modification
- Transport != Application Protocol
- Testcase Delivery != Testcase Consumption
- Input Bytes != Executed Instructions
- Input Artifact != Firmware Path
- Input Artifact != Vulnerability
- Hardware Breakpoint != Passive Observation
- Hardware Breakpoint Reachability != Natural Timing Evidence
- Single-Step Order != Natural Runtime Timing
- Software Breakpoint != Unchanged Program Bytes
- Register Read != Register Write
- Observed State != Injected State
- Source-Declared Instruction != Executed Instruction
- Static Instruction != Runtime Observation
- Static CFG Successor != Runtime Transition
- Source Sequence Order != Runtime Order
- Register Access Semantics != Register Value Observation
- Processor Behavior Fragment != Attack Chain
- SOURCE_DECLARED != RUNTIME_OBSERVED
- STATIC_DECODED != RUNTIME_OBSERVED
- Same Source Artifact != Same Derivation Nature
- STATIC_DECODED != STATIC_INFERRED
- Mixed Nature Allowed != Mixed Source Allowed
- Static Instruction Identity != Dynamic Execution Occurrence Identity
- Occurrence Ordinal != Program Address
- Occurrence Ordinal != Static Source Ordinal
- Source Ordinal != Program Address
- Mnemonic Equality != Semantic Equivalence
- Raw Encoding Equality != Runtime Execution
- Register Name != Register Value
- Register Reference != Register Observation
- Decoded Register Write != Runtime Register Value
- Register Access != State Satisfaction
- Unknown != Zero
- Absent Observation != False
- State Fact != Trigger Requirement
- State Fact != Requirement Satisfaction
- Privilege Label != Verified Runtime Privilege
- Memory Address != MMIO
- Decoded Load/Store != Runtime Memory Access
- Memory Access Semantics != Observed Memory Value
- Decoded Branch Target != Runtime Taken Branch
- Call Instruction != Function Execution
- Return Instruction != Observed Return
- SOURCE_SEQUENCE != STATIC_CFG_SUCCESSOR
- STATIC_CFG_SUCCESSOR != RUNTIME_PRECEDES
- DATA_DEPENDENCY != Runtime Data Value
- CONTROL_DEPENDENCY != Runtime Branch Taken
- Runtime Order != Causality
- Runtime Order != Hardware Trigger
- CFG Edge != Runtime Edge
- CFG Reachability != Symbolic Feasibility
- CFG Reachability != Causality
- Processor Behavior Fact != Hardware Trigger Requirement
- Behavior IR != Trigger IR
- Behavior IR != Matcher Result
- Hardware Trigger Requirement != Requirement Satisfaction
- Trigger Specification != Runtime Trigger
- Trigger Specification != Verified Vulnerability
- Fact Nature != Requirement Nature
- Requirement Slot != Source Ordinal
- Requirement Slot != Runtime Occurrence
- Requirement Collection Order != Required Execution Order
- SOURCE_SEQUENCE != REQUIRED_PRECEDES
- REQUIRED_PRECEDES != STATIC_CFG_SUCCESSOR
- REQUIRED_PRECEDES != RUNTIME_PRECEDES Observation
- Required Immediate Precedence != Observed Adjacency
- Required Exception Event != Observed Exception Event
- Register State Requirement != Register Access Requirement
- Lexical Operand Constraint != ISA Semantic Equivalence
- ProcessorFuzz Source Association != Trigger Correctness Or Minimality
- Trace Observation != Processor Ground Truth
- Evidence Level != BehaviorFactNature
- BYTE_VERIFIED != Producer Authenticity
- Aligned Difference != Trigger
- First Observed Divergence != First Causal Error
- First Divergence In Scope != Global First Error
- Divergence Evidence != HardwareTriggerSpec
- ISA_SIDE != Architectural Truth Automatically
- RTL_SIDE != Physical Silicon
- COV != Cycle
- COV != Timestamp Or Retirement Ordinal
- Printed WDATA Sentinel != Architectural Register Write
- Internal FPR Representation != Architectural IEEE Value
- Same PC != Same Trace Occurrence
- Content Correlation != Production Provenance
- CORRELATED_ARTIFACT_SET != AUTHENTICATED_RUN
- Stale Artifact != Evidence
- Unbound Note != Current Case Metadata
- Mixed Transition Record != Current Run Evidence

真实客户端分析绑定固定 hardware + immutable original firmware，可使用 byte-identical 离线副本。
不得用 patch/recompile/instruction insertion、JTAG code injection 或修改程序字节的 software breakpoint
推导原始目标可达性。任何注入状态都必须与自然达到的状态分开。

跨层只限同一架构内真实软硬件接口关联。Type I 需要 software-vulnerability enabling link；
Type II 不伪造 software vulnerability；Type III 不反转已有路径冒充 hardware→software 客观因果。
R0/V2-1/V2-2 不实现这些检测或验证能力，也不包含 claimed cross-layer positive fixture。
V2-2 仅新增 processor facts 的数据合同；synthetic RISC-V/ARM 示例不是实际解码、SI finding 或客户证据。

当前真实硬件参考输入为 hardware-team-confirmed valid SI 所在的完整 Hardware Case Bundle。
“有效”是硬件团队提供的来源确认，不由 ChipChain 本轮独立验证；bundle 丰富程度不构成证明强度升级。
SI、ISA/RTL artifacts 与 signatures 将来可能支持提取、缩减和根因定位，但须先审计其实际语义；
SI structural parser 与 SOURCE_DECLARED mapper 已由 V2-3B 冻结；V2-4 仅新增 Hardware Trigger
requirements 的内部合法性合同。V2-5A.1 新增 case-output parser 与 non-causal comparison，但没有
真实提取的 trigger、满足性判断、跨层确认或真实 silicon 结论，材料保持 local-only。
真实 confirmed SI 尚未缩减或构造为真实 trigger spec。synthetic examples 不是 ProcessorFuzz finding 或客户证据。
V2-5A 只读审计完成，不表示 provenance-complete：disassembly 与 ELF 不一致而隔离，note 未绑定，
transition.db 的 run identity 未解决。V2-5A.1 的 293-key 支持是限定字段和来源的相关关系，
不证明文件生成关系或 authenticated run。前一条 csrrw 不被标记 causal；DELAYED 不猜测关联，
缺失 mode/state 不补零，COV/WDATA/internal FPR 不自动成为 architectural state/time。
新 observations 不自动投影为 RUNTIME_OBSERVED ProcessorBehaviorFragment，不派生 Trigger requirements。
V2-5A.2 anchor binding、V2-5B LLM-assisted extraction/reduction 另行授权；LLM 不参与本轮证据生成。
Rocket/ProcessorFuzz 是项目负责人提供的 family 声明；unspecified local IDs 不补全版本、配置或 ISA。

Bundled GDBFuzz Serial Example != Proof That Arbitrary Firmware Requires No Adaptation。
SUTConnection 是主机端 input delivery；示例 ready-marker/长度/testcase 握手与示例固件相互匹配。
真实客户工作流必须用 host adapter 匹配既有固件协议，不能修改固件加 harness。
镜像不可变不代表运行未扰动；halt/step/reset/software-breakpoint 必须保留各自 provenance。
