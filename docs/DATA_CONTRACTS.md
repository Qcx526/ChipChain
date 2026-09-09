# V2-R0 / V2-1 数据合同

## 模型与架构

`DomainModel` 拒绝 extra fields、冻结字段赋值、验证默认值并重新验证 nested model instances。
它不自动生成 ID 或时间。R0 具体模型只包含不可变标量；未来集合应使用 tuple 等不可变类型。
Pydantic frozen 不会自动冻结任意 list/dict，也不能替代面向不可信数据的重新验证。

`Identifier` 是非空 ASCII token：首字符字母/数字，其余可为字母、数字、`.`、`_`、`:`、`-`。
不自动 trim，不接受路径或自由文本。它是词法约束，不保证外部来源真实性。
`Architecture.RISC_V = "riscv"`，`Architecture.ARM = "arm"`；没有隐式 alias 或 backend registry。
未来架构需显式扩展词汇及 adapter/profile；未知词汇当前拒绝。

## 单一身份工具

`canonical_json_bytes(payload)` 只接受原生 JSON-compatible values：null、bool、str、int、finite float、
list 和 string-key dict；拒绝隐式类型转换、NaN/Infinity、循环引用和非字符串 key。
输出 UTF-8、sorted keys、无多余空格；保留 array order、Unicode 内容与数值表示差异（如 1 和 1.0）。
这是 V2 的 Python JSON 编码规则，不声称实现跨语言 RFC 8785。

`deterministic_id(namespace, payload)` 输出 `namespace:SHA256(canonical_json_bytes(payload))`。
namespace 必须以小写字母开头，其余允许小写字母、数字、`.`、`_`、`-`。
未来模型应使用显式版本化 namespace；所有 identity-bearing fields 必须由调用方传入。
模型先显式 `model_dump(mode="json")` 再哈希；工具不读取文件、环境、当前时间或生成随机值。
V2 identity 独立于 `archive/phase10-foundation` 中冻结的历史 ID。

## ArtifactProvenance

| 字段 | 含义 |
| --- | --- |
| artifact_id | 必需的稳定来源 token；不自动生成 |
| artifact_sha256 | 必需，恰好 64 个 hex 字符；大写输入规范化为小写 |
| source_kind | 必需、caller-declared 的来源类型 token，不表达信任或验证级别 |
| architecture | 可选架构；None 表示未声明/不适用，不推断兼容性 |
| producer_profile_id | 可选的稳定工具/生产者 profile token |

模型不读取 artifact bytes、不验证 producer authenticity，也不存路径、confidence、status 或 verdict。
未来消费者必须核对实际消费 bytes 的 SHA；此声明本身不是 byte verification。
它是通用来源基础，不是 ProcessorFuzz/GDBFuzz/firmware 专用 artifact model。

## ProgramAddress

`ProgramAddress(value="0X00001000")` 输出 `{"value":"0x1000"}`，零规范化为 `0x0`。
只接受显式 hex 字符串；负数、decimal、整数输入、空白、空串、缺 digits 和 malformed text 均拒绝。
地址不限定 ISA 宽度，也不推断 virtual/physical、MMIO、execution 或 memory access。

Artifact Provenance != Evidence Truth；Artifact SHA != Vulnerability Verdict。
Architecture Vocabulary != Production Backend Support。

## V2-1 来源与目标

所有新模型继承 R0 的 closed/frozen/revalidation 规则，不修改 R0 编码算法或架构拼写。
以下 `id` 都是只读派生 property：`deterministic_id("v2-…-v1", model_dump(mode="json"))`，
完整已规范化字段参与 descriptor ID；不接受或序列化调用方提供的 `id`，JSON roundtrip 后重算。
字段/语义扩展需明确演进版本，不能悄悄复用旧 namespace。

| 合同 | 必需声明与边界 |
| --- | --- |
| HardwareTargetIdentity | target_id、architecture、hardware_model；revision/ISA profile 可未知；不推断 hardware applicability |
| ImmutableFirmwareArtifact | provenance + hardware_target；firmware architecture 必需并匹配 target，可选固件 ISA profile |
| ProcessorFuzzArtifact | raw SI provenance + 独立 hardware_target；显式架构/producer profile，不解析、不声称 minimized 或客户端可复现 |
| GDBFuzzArtifact | campaign output/context provenance + 完整 firmware snapshot；显式架构/producer profile，不推断 coverage/crash 结果 |
| ExternalInputEndpoint | endpoint_id、hardware_target、transport；application protocol 单独声明 |
| InputDeliveryProvenance | producer tool/profile、host adapter profile、endpoint；可选 framing/synchronization/reset profiles |
| ExternalInputArtifact | input provenance + firmware + delivery；可选 strict nonnegative byte_length，不嵌入 raw bytes |
| DebugProvenance | firmware + producer profile + observation mode + 显式非空 perturbations |

firmware 的 artifact_id/SHA/architecture 只在嵌套 provenance 中保存一次；target 只在 hardware_target 中保存。
GDBFuzz/Input 消费者有 expected firmware 时必须调用 `require_firmware(expected)`：双方重新验证 serialized
snapshot，精确比较 artifact ID、SHA、architecture、完整 hardware identity 与固件 ISA profile。
同 ID 不同 SHA、同 model 不同 revision、同架构不同 target 均不能默默绑定。
Input delivery 的 endpoint target 必须等于 firmware target；input bytes 可以无 ISA，若声明架构则必须匹配。
这些检查只比较声明一致性，不核验源文件或判断适用性；V2-1 没有自动使用这些来源的执行路径。

byte-identical 离线副本只有在调用方保留 exact artifact ID/SHA 时才能使用同一 artifact binding。
复制来源的 source_kind/producer 变化会改变 descriptor ID，但不改变其保留的 artifact ID/SHA；
`require_same_target` 不要求两份声明的 producer 相同，也不会仅因 SHA 相同自动合并不同 artifact ID。

## V2-1 输入与调试词汇

Transport 为 `serial_uart/can/lin/usb/network/spi/i2c/other_declared`；OTHER 必须且仅能带
`declared_transport_id`。它不是应用协议，也不是已实现 adapter 列表。
同步模式为 `unknown/target_ready_marker/host_initiated/declared_profile`；DECLARED 必须有 profile，
UNKNOWN 禁止 profile。未提供 framing/reset profile 不等于无 framing/reset。

Debug mode 为 `passive_read/non_halting_trace/hardware_breakpoint_halt/manual_halt/single_step/`
`software_breakpoint/state_write/reset/reset_halt`，不是 ChipChain 支持能力列表。
Effects 为 `unknown/none_observed/halt_induced/step_induced/program_bytes_may_be_modified/`
`state_injection/reset_induced`。集合无序、拒绝重复并规范排序；unknown/none_observed 只能单独存在。
halt 模式必须声明 halt，step 必须声明 step，软件断点必须声明可能修改程序字节，state write 必须声明
injection；reset_halt 同时要求 reset 与 halt。Passive/non-halting 不接受 active control effects。
矛盾组合拒绝而不是自动填充。`none_observed` 仅是声明，不是 non-interference 证明。
Debug firmware 指向原始参考镜像，不能把软件断点的 patch observation 伪装成原始字节证据。

GDBFuzz 示例握手仅是特定 host/firmware 协议；core 端点不命名为 SUTConnection，不增加 firmware API。
全部合同无 Evidence、verdict、confidence、score 或 host path 字段，不做文件/硬件/网络 I/O。
