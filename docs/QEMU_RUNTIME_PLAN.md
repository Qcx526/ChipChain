# QEMU Runtime Plan

Phase 9B0 的 backend-neutral runtime contract 已完成。Phase 9B1 的 ARM passive observer
离线实现、fixture 和测试已完成；当前机器没有 QEMU、supported GCC/Clang + GLib build
environment、plugin headers 或已编译 plugin，因此真实 observer validation 明确为
`BLOCKED`，不能声称阶段完成。

## Phase 9B1 implemented boundary

```text
Owned ARM32 ELF
  → qemu-system-arm / virt / cortex-a15 / TCG / 1 vCPU
  → dumb passive TCG plugin
  → chipchain_qemu_raw_trace v1 JSONL
  → strict Python parser
  → RuntimeTrace detached revalidation
  → interaction-agnostic Dynamic Evidence
```

两层 probe 分离职责：Python 执行 `qemu-system-arm --version`，只证明 executable 可运行并
记录 version；plugin header 从 `qemu_info_t` 证明 target=`arm`、system emulation、单 vCPU
以及 API min/current。不能从 binary name 推断 plugin capability。QEMU 11.0.3 是首个计划
验证的 reference environment，不是硬编码 allow-list。

Plugin 仅声明 instruction execution、memory access、physical address 和 IO classification。
它使用 instruction/memory callbacks，只在 `qemu_plugin_hwaddr_is_io()` 为 true 时发出 MMIO，
并从 QEMU API 获取 physical address、read/write 和 access size。不读 memory value/register，
不注入 interrupt/DMA/fault，不修改 PC、register 或 memory。

## Completion gates

Offline contract gate 已实现：strict models/parser、raw SHA-256 provenance、RuntimeTrace adapter、
safe argv runner、timeout/incomplete fail-closed、owned deterministic ELF、mocked subprocess tests
和文档。默认 pytest 不读取 QEMU 环境变量，也不要求网络或外部工具。

Real observer gate 仍需在一个一致的 QEMU SDK/runtime 环境完成：

1. 编译并加载 passive plugin；
2. 运行 owned ARM ELF 并正常 semihosting exit；
3. 观察真实 instruction callback；
4. 观察 QEMU IO-classified UART MMIO write 和 physical address；
5. 解析真实 JSONL，构造 RuntimeTrace 和 Dynamic Evidence。

只有两个 gate 都通过才能称 Phase 9B1 complete。真实测试由
`CHIPCHAIN_RUN_QEMU_TESTS=1` 显式开启。

## Next stage

Phase 9B2 候选范围是 Dynamic Interaction Fact Verification 与 Static/Dynamic Aggregation：
显式 binding、事实 verifier、聚合和 conflict policy。Type III causal verification 不自动承诺
在 9B2 完成；它仍需要可比 baseline/intervention、实际 propagation 与 affected execution，
不能从事件先后次序推出。
