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

真实客户端分析绑定固定 hardware + immutable original firmware，可使用 byte-identical 离线副本。
不得用 patch/recompile/instruction insertion、JTAG code injection 或修改程序字节的 software breakpoint
推导原始目标可达性。任何注入状态都必须与自然达到的状态分开。

跨层只限同一架构内真实软硬件接口关联。Type I 需要 software-vulnerability enabling link；
Type II 不伪造 software vulnerability；Type III 不反转已有路径冒充 hardware→software 客观因果。
当前 R0 不实现这些检测或验证能力，也不包含 claimed cross-layer positive fixture。
