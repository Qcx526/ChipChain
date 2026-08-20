# ARM QEMU Passive Runtime Observer

## Scope and status

Phase 9B1 只支持 ARM 32-bit system emulation、`virt`、`cortex-a15`、TCG 和一个 vCPU。
QEMU 11.0.3（plugin API v6）是首个 reproducible reference environment。核心逻辑始终 probe 并记录实际
QEMU/version/plugin API，不以 `version == 11.0.3` 放行其他环境。

当前仓库状态是 `IMPLEMENTATION_COMPLETE_REAL_VALIDATION_BLOCKED`：Python contracts、C
source、owned ELF、offline tests 与 smoke runner 已实现；当前开发机缺少
`qemu-system-arm`、supported GCC/Clang + GLib build environment、`qemu-plugin.h` 和
compiled plugin，未产生真实 trace。

## Trust boundary

C plugin 是 dumb observer。它只复制 translation-time instruction PC，并在 memory callback
中查询 QEMU 的 hardware-address handle。只有 QEMU 返回 handle 且
`qemu_plugin_hwaddr_is_io()` 为 true 才输出 `mmio_read`/`mmio_write`。Store/load、physical
address 和 access size 分别来自 memory-info、`qemu_plugin_hwaddr_phys_addr()` 与
`qemu_plugin_mem_size_shift()`；没有 opcode parsing 或地址范围猜测。

Plugin API 返回的 paddr 在多 address-space 环境可能不唯一。Phase 9B1 无可靠
address-space semantic identity，所以 `address_space_id=null`；不得发明 `system-memory`。
RAM access 不转成 RuntimeObservation，memory value/value width 保持 null。

Plugin 不输出 vulnerability、CVE、interaction、reference role、verification、score 或 root
cause，不调用 register/memory/PC mutation API，也不观察或注入 interrupt、exception、DMA、
fault。即使真实 MMIO 被观察到，也只表示该运行中发生了 IO-classified memory access。

## Raw JSONL v1

Raw artifact format 是 `chipchain_qemu_raw_trace` version 1，不是 RuntimeTrace JSON。它严格为：

1. 唯一且首条 `header`：plugin identity/build API、target、runtime API min/current、system
   emulation、vCPU facts 和 run ID；QEMU executable version 由 Python 独立 probe。
2. 零到多个 `event`：连续全局 `sequence_index=0..N-1`。Instruction 只有 PC；MMIO 还含
   virtual/physical address、`is_io=true` 与 byte access size。
3. 唯一且末条 clean `end`：event count、last sequence 和 `clean_shutdown=true`。

Parser 将文件视为 untrusted input，拒绝 malformed JSON、blank/trailing/unknown records、额外
字段、wrong plugin/target/mode/vCPU/API、未知 event、缺失 paddr、`is_io=false`、duplicate/gap
sequence 和缺失 end。原始字节 SHA-256 进入 RuntimeTraceManifest provenance；合法的字节变化
也会改变 manifest identity。

## Runtime mapping

Executable probe 与已验证 plugin header 合成 path-independent environment identity。
`RuntimeBackendManifest` 使用 `qemu_tcg_plugin`，只声明：

- `instruction_execution`
- `memory_access`
- `physical_address`
- `io_classification`

Adapter 映射 instruction/MMIO 事件，设置 `value=null`、`value_width_bits=null`、
`address_space_id=null`，然后调用 `revalidate_runtime_trace()`。只有该 detached RuntimeTrace
中的 Observation 才能交给 `RuntimeEvidenceNormalizer`。Trace manifest 明确保留 owned、
synthetic、fixture、not-real-vulnerability 和 non-benchmark input provenance。生成的
`Evidence(type=dynamic_analysis, verified=true)` 表示 observation contract/integrity verified；
不表示漏洞、Interaction、因果、触发、可利用性或攻击链成立。

## Owned fixture and runner

`tests/fixtures/qemu_arm_baremetal` 是 owned/synthetic/fixture，明确不是真实漏洞或 Benchmark。
生成器从有注释的 A32 machine words 构造 deterministic ELF32：执行正常指令、向 reference
QEMU `virt` UART0 写一个 byte，再用 Arm semihosting `SYS_EXIT` 正常退出。

QEMU `virt` RAM 从 `0x40000000` 开始，bare-metal 启动时生成的 DTB 位于 RAM 起始区域。
因此 Phase 9B1 owned fixture 有意链接/加载到 `0x40200000`，不得链接回 `0x40000000`。
`0x40200000` 只是 QEMU 11.0.3 owned-fixture placement，不是 ARM architecture rule。

`0x09000000` 只属于 QEMU 11.0.3 version-pinned fixture ground truth；它不是 ARM 通用 MMIO
规则，device address 可随 QEMU version/machine 改变。Semihosting 只允许该 trusted owned
fixture，不能对 untrusted firmware 开启。

Runner 使用 argv list 与 `shell=False`，固定 `virt`/`cortex-a15`/`smp 1`/TCG/generic loader，
拒绝会破坏 QEMU comma-delimited options 的路径和 run ID。Timeout、nonzero exit、missing raw
file 或 missing clean end 全部 fail closed，不能产生 Evidence。

## Build and real validation

项目不会下载或安装 QEMU、compiler、headers、GLib 或预编译 plugin。准备同一版本的
QEMU runtime/SDK 后：

```powershell
$env:CHIPCHAIN_QEMU_SYSTEM_ARM = 'C:\path\to\qemu-system-arm.exe'
$env:QEMU_PLUGIN_INCLUDE = 'C:\path\to\headers'
$env:CHIPCHAIN_QEMU_PLUGIN_CC = 'C:\path\to\compiler.exe'
.\.venv\Scripts\python.exe tools\qemu_plugins\build.py
$env:CHIPCHAIN_QEMU_PLUGIN = 'C:\path\to\chipchain_runtime_observer.dll'
.\.venv\Scripts\python.exe scripts\qemu_phase9b1_smoke.py
$env:CHIPCHAIN_RUN_QEMU_TESTS = '1'
.\.venv\Scripts\python.exe -m pytest tests\test_qemu_real_integration.py -q
```

成功报告必须来自真实 plugin header/events/end，并记录 QEMU version、plugin API、event counts、
MMIO paddr 与 Evidence ID。缺任一组件时必须报告 `REAL_QEMU_STATUS = BLOCKED`。
