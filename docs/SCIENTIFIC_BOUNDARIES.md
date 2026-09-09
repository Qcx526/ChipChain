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

真实客户端分析绑定固定 hardware + immutable original firmware，可使用 byte-identical 离线副本。
不得用 patch/recompile/instruction insertion、JTAG code injection 或修改程序字节的 software breakpoint
推导原始目标可达性。任何注入状态都必须与自然达到的状态分开。

跨层只限同一架构内真实软硬件接口关联。Type I 需要 software-vulnerability enabling link；
Type II 不伪造 software vulnerability；Type III 不反转已有路径冒充 hardware→software 客观因果。
R0/V2-1/V2-2 不实现这些检测或验证能力，也不包含 claimed cross-layer positive fixture。
V2-2 仅新增 processor facts 的数据合同；synthetic RISC-V/ARM 示例不是实际解码、SI finding 或客户证据。

Bundled GDBFuzz Serial Example != Proof That Arbitrary Firmware Requires No Adaptation。
SUTConnection 是主机端 input delivery；示例 ready-marker/长度/testcase 握手与示例固件相互匹配。
真实客户工作流必须用 host adapter 匹配既有固件协议，不能修改固件加 harness。
镜像不可变不代表运行未扰动；halt/step/reset/software-breakpoint 必须保留各自 provenance。
