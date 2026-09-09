# V2-R0 / V2-1 / V2-2 / V2-3B 数据合同

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

## V2-2 Processor Behavior IR v1

已由 `chipchain-v2-2-stable` 冻结于 `48f8925792a1afa829d20bc25841010e1a12faa2`。

API 位于 `chipchain.behavior.processor`，不进入 core 或 root exports。仅为数据合同，不解析 SI/固件，
不解码、不分析、不创建 Trigger IR 或 verification。未复制历史 Phase-10 模型或 identity。

`BehaviorSourceContext` 保存 artifact provenance、完整 hardware target、producer profile、source kind，
并按来源绑定 V2-1 firmware 或 ProcessorFuzz descriptor；不保存 fragment-wide nature。
每个 record 显式声明自己的 derivation nature；以下是来源兼容范围，不是自动赋值或语义升级：

| source_kind | 允许的 record nature | 额外绑定 |
| --- | --- | --- |
| declared_artifact | SOURCE_DECLARED | 显式 artifact/target |
| processorfuzz_si | SOURCE_DECLARED | 必须 exact ProcessorFuzz provenance/target，不能同时绑定 client firmware |
| firmware_artifact | STATIC_DECODED / STATIC_INFERRED | 必须 exact firmware provenance/target |
| static_analysis_artifact | STATIC_DECODED / STATIC_INFERRED | 必须 firmware snapshot；artifact 可为独立分析产物 |
| runtime_observation_artifact | RUNTIME_OBSERVED | 显式观察 artifact；若绑定 firmware，不得用 firmware artifact 本身冒充 trace |
| synthetic_fixture | SYNTHETIC_FIXTURE | owned test declaration，不是 client evidence |

artifact architecture 必须显式匹配 target；可选 firmware 的完整 target 必须一致。同 artifact ID 的冲突
provenance 拒绝。runtime 分类只是未来 adapter 的 provenance 合同，模型不核验实际观察或认证 producer。
Firmware binding 可从 context.firmware 恢复并用冻结 `require_same_target(expected)` 复核。

每个元素/关系保存 `source_context_id`、architecture、nature；前两者必须与 context 精确一致，
nature 必须与来源兼容且满足关系专属规则。同一固件 context 可保留 decoded 指令 + inferred CFG/data/control
关系，不 relabel、不用 synthetic 绕过。Mixed Nature Allowed != Mixed Source Allowed。
不支持靠同架构将另一个 ProcessorFuzz/client target 的元素注入当前 fragment。

| 元素 | v1 合同 |
| --- | --- |
| InstructionBehavior | 唯一非负 source_ordinal、mnemonic、有序 typed operands；address/encoding/size 可未知；不是 runtime occurrence |
| RegisterAccessBehavior | instruction_id、effect_index、register_ref、READ/WRITE/READ_WRITE；没有 value |
| MemoryAccessBehavior | effect_index、access；可选 instruction_id/width_bytes/MemoryAddress，不推断 atomicity/MMIO |
| ControlTransferBehavior | instruction_id、effect_index、branch/jump/call/return/indirect/exception-return；target 可未知 |
| ProcessorEvent | effect_index、event/cause 语义；可选 instruction_id；运行事件必须有 occurrence_ordinal |
| RegisterStateFact | fact_index、register_ref、必需 value（ExactScalar 或显式 None）；也支持 SYSTEM/CSR namespace |
| PrivilegeStateFact | fact_index、architecture-scoped profile/mode label；None 未知，没有模式排序 |
| MemoryStateFact | fact_index、MemoryAddress、必需 value（ExactScalar 或 None） |

RegisterReference 区分 architecture、class、namespace 与 name；class 为 GPR/SYSTEM/FLOATING_POINT/VECTOR/SPECIAL。
`csr` 只是相关架构下的 namespace 示例，不枚举 ISA 寄存器，也不执行命名等价转换。
Operands 分 register/scalar/declared-text；文本是显式来源表示，不解析表达式或证明语义等价。
Encoding 是**按来源字节顺序**的小写 hex，无 `0x` 前缀；拒绝奇数长度/非法字符。有 encoding 时必须给出
一致的正整数 size_bytes；允许 2/4/6 等宽度仅说明通用字节合同，不证明该编码对某 ISA 合法。
没有 encoding 时 size 可未知；不根据 ordinal 制造地址，不按整数 endianness 重排 bytes。
ExactScalar 为显式 width_bits + unsigned hex bit pattern，规范为 `0x…` 并检查溢出；不把未知、symbolic、
未观察值变成零。None 与 zero 的 ID 不同。MemoryAddress 不接受 ProgramAddress 对象，也不分类地址空间。

| 关系 | 非 synthetic fragment 的性质限制 |
| --- | --- |
| SOURCE_SEQUENCE | SOURCE_DECLARED / STATIC_DECODED / STATIC_INFERRED；指令 ordinal 严格递增，不要求相邻 |
| STATIC_CFG_SUCCESSOR | STATIC_INFERRED；端点必须为指令，允许静态 self-loop |
| DATA_DEPENDENCY / CONTROL_DEPENDENCY | STATIC_INFERRED；仅声明，不运行 dataflow/CFG 引擎 |
| RUNTIME_PRECEDES | RUNTIME_OBSERVED；仅连接有 occurrence_ordinal 的 ProcessorEvent；拒绝 self-loop/cycle，不表示 causality |

SYNTHETIC_FIXTURE 可测试全部关系词汇，但所有元素和关系也必须标记 synthetic。运行顺序回归只使用
这种 fragment，没有真实目标运行例子。静态 adapter 不能凭地址排序构造 RUNTIME_PRECEDES。

`ProcessorEvent.occurrence_ordinal` 是 source-local 唯一非负整数：RUNTIME_OBSERVED 必需，
SYNTHETIC_FIXTURE 可显式提供，其他 nature 禁止提供；None 表示非 occurrence 的事件语义。
它不是 ProgramAddress、InstructionBehavior.source_ordinal 或 wall-clock，也不自动生成顺序关系。
`effect_index` 仍是 effect slot，不充当执行计数。同一静态指令可被 A@1/A@3 分别引用；
synthetic A@1 → B@2 → A@3 → B@4 是四个事件上的顺序，不是静态 A/B 节点的环或 runtime evidence。

Fragment 的 elements/relations 是无序 tuple 集合，拒绝重复 ID 后按派生 ID 排序；不会默默去重。
指令 source ordinal 在 fragment 内唯一；effect_index 在同 kind/instruction 内唯一，ProcessorEvent 还按
occurrence_ordinal 区分 effect slot；occurrence ordinal 本身在 source-local fragment 内唯一。
fact_index 在同 state kind 内唯一。
所有关系端点必须存在；instruction_id 必须指向本 fragment 的 InstructionBehavior，不能指向任意元素。
顺序环检查仅拒绝结构矛盾，不求 firmware 可达性。空 fragment 允许，表示未提供事实，不是否定结论。

所有派生 ID 复用 R0 deterministic_id 与 `v2-processor-…-v1` namespace，为只读属性而非 caller-supplied ID。
context 改变会改变绑定元素/fragment identity，引用需显式重建；关系类型、ordinals、operands、state width/value
等均参与 identity。JSON roundtrip 重算 ID。fragment contract 字符串固定为 `v2_processor_behavior_fragment_v1`。
冻结/tuple/nested revalidation 防止调用方普通输入突变影响 retained fragment；不能用 unchecked
`model_construct`/`model_copy(update=…)` 绕过验证后把结果当 authoritative input，必须重新 model_validate。

## 本地 Hardware Case Bundle（文档级概念）

当前来源为硬件团队报告有效 SI 的完整 case：**hardware-team-confirmed valid SI testcase**。
该确认是外部 provenance/context，不是 ChipChain verified hardware vulnerability、silicon verification
或 root-cause proof。Hardware Case Bundle 不是新增 production model，也不改变冻结 V2-1/V2-2 合同。

V2-3A.1 本地清点：`hardware_buginfo/testis/` 含 101 个文件、17 个目录（含 `testis/`）；
已存在解压材料，仓库内未发现 RAR 原包，不能声称核验了给定 archive SHA 或解压内容与原包的逐项一致性。
两个 SI 位置分别为 `testis/tests/.input_918_gen.si` 和 `testis/out/tests/.input_1.si`，
均为 26671 bytes，SHA-256 均为
`cb6dbcbd7d67a78bc5f070342ff03178562ded53edf3f2467db26d999059e1f6`。
这是同一 exact SI bytes 的两个 workflow locations，不是两个独立 findings。
Parser 绑定实际消费 bytes 的 SHA，mapper 再核对显式 ProcessorFuzzArtifact，不能把 filename/CRC 当身份。

以下均为观察布局的结构角色，未确认精确生成语义：

| 角色 | 本地 case 路径（相对 `testis/`） |
| --- | --- |
| Source testcase | `tests/.input_918_gen.si`、`out/tests/.input_1.si` |
| Derived build representation | `out/tests/` 下的 `.input_1.S`、`.input_1.elf`、`.input_1.hex`、`.input_1.symbols`、`disassembly.asm` |
| Execution/simulation artifacts | `out/trace/` 下的 `isa_1.csv`、`isa_1.log`、`rtl_1.log` |
| Comparison/signature artifacts | `out/.isa_sig_0.txt`、`out/.rtl_sig_0.txt` |
| Other state/context | `out/transition.db`、`note.log`、`build/` 的 Verilator/RocketTile 等文件 |

不从命名推断实际执行、硬件 target、差异原因或 vulnerability；本阶段不解析日志、signature、数据库或二进制。
V2-3B 的最初 projection 仅允许 SOURCE_DECLARED 指令、确定性支持的 RegisterOperand/DeclaredOperand、
SOURCE_SEQUENCE；没有额外语义证据时不生成 RegisterAccessBehavior、MemoryAccessBehavior、
ControlTransferBehavior、ProcessorEvent、PrivilegeStateFact、RegisterStateFact 或 MemoryStateFact。

根目录 `/hardware_buginfo/`、`/hardware_caseinfo/` 均为 `LOCAL_ONLY_REAL_ARTIFACT`，后者是首选语义名称；
不自动移动/重命名/改写材料，不默认提交真实 SI、ISA/RTL trace 或其他 case 内容。

## V2-3B confirmed SI parser / mapper（本地实现，待冻结）

公开 API 位于 `chipchain.adapters.processorfuzz`：
`parse_processorfuzz_si(data: bytes, *, parser_profile_id=...) -> RawProcessorFuzzSI`；
`map_processorfuzz_si(raw_si, source: ProcessorFuzzArtifact) -> ProcessorBehaviorFragment`。
Parser 无路径或 target 参数，对同一 immutable bytes 计算 SHA 并 strict decode。
Raw SI、instruction、data IDs 使用冻结 deterministic_id 与 `v2-processorfuzz-…-v1` namespaces；
路径、时间和随机值不参与身份。相同 bytes 的两处 workflow copy 得到相同 raw ID。

`processorfuzz_si_confirmed_v1` 是本地 confirmed-case 语法 profile，不是上游 ProcessorFuzz profile。
它只接受 ASCII/LF、末尾 LF、首行 `p-m`、空第二行、按 `_p/_l/_s` 顺序出现的标签族、
labeled instruction / 8-space indented continuation、一次 `data:` 与非空小写 16-hex-digit 数据行。
不固定真实样本的指令/data 数量；不支持 BOM、CRLF、tab、注释或猜测的空行位置。
标签不重复；instruction/data ordinal 来自物理记录顺序，不来自标签数字。

Raw instruction 保存行号、ordinal、可选 label、mnemonic、有序 operand_tokens、可选 trailing_token
及 exact raw_line（包含空格）；data 保存行号、ordinal、hex_token。两种 record 提供不含 LF 的
`raw_line_sha256` 派生属性。Raw 文件通过 `exact_bytes()` 重建固定分隔符与原行，重新校验字段/位置/
byte_length/snapshot_sha256；嵌套 tuple/revalidation 防止调用方修改已保留的对象。

Confirmed 文件的 `0000` 尾列全部始于第 51 列，前有至少两个空格。只有完整指令后的该列 token
才视为 trailer；逗号等待 operand 时优先保留 `0000` operand。无依据的歧义或非该列的额外 token 拒绝。
原行不改写。裸 mnemonic 只支持本例观察到的 fence/fence.i/mret/sret/uret；带操作数的 mnemonic
只做词法校验，不承诺指令存在或 operand arity/ISA 合法。未观察的 ecall/ebreak 裸形式当前拒绝。

GPR/FPR 识别 x0–x31/f0–f31；本例出现的 zero 保留字面 spelling，不改成 x0。t0 未在当前 confirmed SI
出现，不从旧候选集合扩展支持。CSR 只识别当前 16 个符号：fcsr/mcause/mepc/mip/mstatus/mtval/
pmpaddr1/pmpaddr2/pmpaddr6/pmpaddr7/pmpcfg0/scause/sepc/sip/sstatus/uepc，映射到 SYSTEM/csr。
其余已支持的 decimal/negative/hex、标签、d_/pt 符号、offset(register)/(register)、rounding token
保持 DeclaredOperand，包括 `-0`；不创建 ExactScalar、不推断 width、读写或 CSR 实现支持。
未定义符号不解析为地址。Header、标签分组、trailer 含义及 data 地址/布局/endianness 均未解决。

Mapper 对 raw/source 的 serialized snapshots 重新验证，要求 RISC-V 和 exact SHA 一致，原样保留
artifact ID/SHA、完整 target 和 producer profile，构造 PROCESSORFUZZ_SI source context。
每条 raw instruction 恰好一个 SOURCE_DECLARED InstructionBehavior，address/encoding/size 均为 None；
仅在连续指令间建立 SOURCE_DECLARED SOURCE_SEQUENCE。其余 raw 内容故意不投影，不生成任何 access、
state、event、CFG、dependency、runtime order、Trigger 或 verdict。Partial Projection != Parser Failure。
异常基类为 ProcessorFuzzSIError，子类为 ProcessorFuzzSIParseError、ProcessorFuzzSIIntegrityError、
UnsupportedSIProfileError；
parser/mapper 异常只含安全类别/原因与必要行号，不输出真实 source line 或 Pydantic input dump。

### 当前真实来源声明与未知项

项目负责人声明 architecture=RISC-V、hardware model=Rocket、producer family=ProcessorFuzz。
本地验收使用 caller-declared `artifact_id="local-confirmed-processorfuzz-si"`，source_kind 为
`project-owner-declared-processorfuzz-si`，exact SHA 为上节已记录值；不是从路径或 bytes 推断 artifact ID。
`target_id="rocket-unspecified-config"`、`hardware_model="Rocket"`，hardware_revision 与
instruction_set_profile_id 均为 None。RV32/RV64、具体 Rocket 配置与 ISA extensions 不推断。
`producer_profile_id="processorfuzz-unspecified-profile"` 明确表示已知工具 family、未知版本/commit/config，
不是实际 upstream profile 名称，也不与 parser_profile_id 混用。
这些声明允许当前真实 SI 的本地保守映射，但不认证 producer、不证明 hardware applicability 或 client
target 等价。缺少必要声明时仍只 structural parse，禁止给真实 SI 附 synthetic provenance。
本地验收：两份 SI 的 raw payload/ID 相同，header 为 p-m、368 条指令、208 个标签、341 个 trailer、
384 条 data；使用以上部分声明分别映射得到相同 fragment ID、368 个指令和 367 个 SOURCE_SEQUENCE。
这仅为 parser/mapper 合同验收，不是硬件执行或漏洞验证；原 case 文件未改写，也未加入默认 fixtures。
