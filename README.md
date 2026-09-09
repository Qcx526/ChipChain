# ChipChain V2

RISC-V-first 跨层硬件触发与可达性研究，使用架构中立的核心合同。
真实客户端目标是 **固定硬件 + 不可变的原始固件**；只分析原件或字节完全一致的离线副本。
`RISC-V-first != RISC-V-only`：ARM 及其他架构将通过独立 profiles/adapters/backends 扩展。

核心研究问题：

```text
FirmwareExecutionPath |= HardwareTriggerSpecification ?
```

未来工作流（尚未实现）：

```text
ProcessorFuzz SI → SI Adapter → Trigger Extraction / Reduction → Hardware Trigger IR
External Input → Original Immutable Firmware → Firmware Execution → Processor Behavior IR

ChipChain: Processor Behavior + Trigger Extraction + Trigger Matching + Reachability
```

未来以 Processor Behavior IR 连接两侧行为，提取/缩减结果用 Hardware Trigger IR 表达，
再进行 Trigger Matching 和 Anchored Reachability；客观证据验证在其后。
开发时可先定义 Trigger IR 合同再实现 Extractor，开发依赖顺序不等于运行数据流。
所有跨层关联必须发生在同一架构内，不能拼接 ARM 固件与 RISC-V 硬件来源。

## 当前范围：V2-1 合同基础

V2-R0 已冻结；V2-1 在其基础上新增硬件目标、精确固件、ProcessorFuzz/GDBFuzz 来源、
外部输入端点/投递/输入 artifact，以及调试扰动声明。它们仅是可验证字段一致性的 core 合同，
不读取文件、不解析来源、不交付输入、不访问硬件。CLI 仍为 R0 `--help`/`--version` shell。
没有跨层 positive example。
RISC-V 是主实验目标，不是已完成的 backend。

| 能力 | 当前状态 |
| --- | --- |
| Processor Behavior IR | NOT IMPLEMENTED |
| ProcessorFuzz integration / RISC-V SI parser | NOT IMPLEMENTED |
| GDBFuzz integration / parsing | NOT IMPLEMENTED |
| RISC-V firmware decoder | NOT IMPLEMENTED |
| Hardware Trigger IR / Trigger Extraction | NOT IMPLEMENTED |
| Trigger Matcher | NOT IMPLEMENTED |
| Anchored Reachability | NOT IMPLEMENTED |
| End-to-end cross-layer detection / evidence-backed Verification | NOT IMPLEMENTED |

LLM 的未来角色是 coordinator/reasoner，不是 processor ground truth。
Knowledge 提供上下文关联，不等于确定性 trigger reachability。

## GDBFuzz 与不可变客户端

GDBFuzz `SUTConnection` 是 **HOST-SIDE input delivery**，不是 firmware API。
其 bundled `SerialConnection` 示例使用“目标 ready marker → host 长度 → testcase bytes”，
示例固件也有对应逻辑；这不能证明任意客户固件无需适配。
真实工作流要求 **既有客户端点 + 匹配既有协议的主机适配器**，不得修改固件加入 fuzz harness。
`Adapt Host Input Delivery != Modify Firmware`；`Custom Host Adapter != Firmware Instrumentation`。
这些是本阶段采用的来源边界，不表示已经运行或集成 GDBFuzz。

## 固件与科学边界

不得通过 patch、recompile、instruction insertion、JTAG code injection 或修改程序字节的
software breakpoint 制造原始固件的 triggerability。注入状态不能被报告为自然到达状态。

- Modified Firmware != Evidence For Original Firmware
- Different Firmware SHA != Same Target
- Injected State != Naturally Reached State
- JTAG Observation != Firmware Modification
- Synthetic Fixture != Client-Target Evidence

完整的静态/动态、匹配/验证边界见 [科学边界](docs/SCIENTIFIC_BOUNDARIES.md)。
Provenance 的字段校验不证明源数据可信；SHA 必须由未来消费者与实际消费的 bytes 核对。

## 开发与检查

Ubuntu 是 canonical 开发环境；Python >= 3.11，默认依赖只有 Pydantic，开发测试使用 pytest。
新环境可安装本项目的开发依赖：

```bash
python -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
```

已有环境的离线检查：

```bash
PYTHONPATH=$PWD .venv/bin/pytest -q
.venv/bin/python -m pytest -q
.venv/bin/python -m compileall -q src tests
.venv/bin/chipchain --help
.venv/bin/python -m chipchain --help
git diff --check
```

默认测试不需要网络、API Key、QEMU、JTAG 或外部数据库。CLI 不加载 `.env`，没有分析命令。

## 文档与历史恢复

- [架构](docs/ARCHITECTURE.md)
- [数据合同](docs/DATA_CONTRACTS.md)
- [路线图](PLANS.md)
- [开发约束](AGENTS.md)

完整 Phase-10 源码、测试、fixtures、goldens 与历史文档保留在 `archive/phase10-foundation`，
由 annotated tag `phase-10-foundation-final` 固定于
`769736f1279fa9d90847801670a8852a5579323e`。可用
`git show archive/phase10-foundation:<path>` 只读检查；未来迁移需显式设计和测试。
V2 沿原 Git 历史演进，有意不保留旧 public imports 或旧 ID 的兼容层。
