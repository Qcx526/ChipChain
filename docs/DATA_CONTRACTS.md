# V2-R0 / V2-1 / V2-2 / V2-3B / V2-4 / V2-5A.1 / V2-5A.2 数据合同

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

不从命名推断实际执行、硬件 target、差异原因或 vulnerability。V2-5A.1 只解析受审计的 trace/log/signature
bytes，不解析 transition.db、stale disassembly 或二进制，也不创建整体 run provenance 合同。
V2-3B 的最初 projection 仅允许 SOURCE_DECLARED 指令、确定性支持的 RegisterOperand/DeclaredOperand、
SOURCE_SEQUENCE；没有额外语义证据时不生成 RegisterAccessBehavior、MemoryAccessBehavior、
ControlTransferBehavior、ProcessorEvent、PrivilegeStateFact、RegisterStateFact 或 MemoryStateFact。

根目录 `/hardware_buginfo/`、`/hardware_caseinfo/` 均为 `LOCAL_ONLY_REAL_ARTIFACT`，后者是首选语义名称；
不自动移动/重命名/改写材料，不默认提交真实 SI、ISA/RTL trace 或其他 case 内容。

## V2-3B confirmed SI parser / mapper（已冻结）

`chipchain-v2-3b-stable` 固定于 `7d42e325beb0385a0e8df16b204c7f8ea296eb5a`。

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

## V2-4 Hardware Trigger IR v1（仅 requirement contracts）

公开 API 为 `chipchain.trigger`，不修改冻结 core/behavior/adapter。以下全部是规范性要求，
不是 Processor Behavior facts、requirement satisfaction、runtime trigger 或 verified vulnerability。
没有 nature/status/score/verdict、固件引用或匹配结果字段，也没有提取/缩减/求值/匹配 API。

`TriggerSourceContext` 保存 artifact、完整 hardware_target、producer_profile_id，source_kind 的 v1
词汇为 `processorfuzz_artifact` / `synthetic_fixture`。artifact 的 architecture/producer 必须显式匹配
context；PF 类型必须且仅能包含 ProcessorFuzzArtifact，其完整 provenance/target 必须分别精确相等。
同 model 不同 target_id/revision/ISA profile 拒绝混用，未知 revision/profile 保持 None，不认证来源。
SOURCE association != trigger correctness/minimality/client applicability。没有 PF descriptor → spec 转换函数。

每个 requirement 带 source_context_id、architecture、严格非负整数 requirement_slot。
slot 在整个 spec（跨 preconditions/steps）唯一；相同内容可通过不同 slot 表达 A(0)/B(1)/A(2)。
slot 不自动重编号，不是 source ordinal/address/runtime occurrence；相同声明节点可被显式复用，
但 order 端点必须存在于当前 spec，不能引用另一个 spec 独有的节点。

| Requirement | v1 内容与边界 |
| --- | --- |
| InstructionTriggerRequirement | mnemonic + positional operands；None 不约束操作数，空 tuple 明确要求零操作数 |
| RegisterAccessTriggerRequirement | RegisterReference + AccessKind；无 value，不证明访问发生 |
| RegisterStateTriggerRequirement | RegisterReference + ScalarConstraint；无未知值自动补零 |
| MemoryAccessTriggerRequirement | AccessKind；width_bytes/MemoryAddress 可选，None 不约束该维度，宽度严格正整数 |
| MemoryStateTriggerRequirement | 必需的 explicit MemoryAddress + ScalarConstraint，不把 symbolic/unknown 变成地址零 |
| PrivilegeStateTriggerRequirement | 显式 profile_id/mode_id，按 requirement architecture 定域，不推断模式支持或排序 |
| ControlTransferTriggerRequirement | ControlTransferKind + 可选 ProgramAddress target；不构造 CFG 或 branch-taken fact |
| EventTriggerRequirement | ProcessorEventKind + 可选 cause_id；无 cause 时不约束原因，不是 runtime occurrence |

RegisterReference 及 instruction 内 register operand 必须匹配 requirement/source architecture；
MemoryAddress/ProgramAddress 沿用各自公开数值合同，不混用、不附加 ISA 或 MMIO 分类。
production 不硬编码 ISA mnemonic/register/model，RISC-V/ARM 测试仅使用显式 synthetic 描述。

`OperandRequirement` 是 any/register/scalar/text 判别联合。AnyOperandRequirement 只放宽该位置；
RegisterOperandRequirement 要求 exact reference；ScalarOperandRequirement 持有 scalar constraint；
TextOperandRequirement 只表达 exact lexical text，不解析 alias/symbol/expression 或判断 ISA 等价。
operand tuple 保留位置，重排改变 ID。

`ExactScalarConstraint(value: ExactScalar)` 表达 actual == value；
`MaskedScalarConstraint(value, mask)` 表达 (actual & mask) == value。
这里只检查声明合法性，**不接收或评估 actual**。value/mask 宽度必须相同、严格正整数，位模式不能溢出，
value 不能含 mask 以外的置位；零 mask 因未约束任何位而拒绝。零 value 在合法 mask 下允许。

`HardwareTriggerSpec.contract` 固定为 `v2_hardware_trigger_spec_v1`。
preconditions 只允许 register/privilege/memory state；steps 只允许 instruction/register-access/
memory-access/control-transfer/event。三组集合（含 order_requirements）使用 tuple，拒绝重复 ID 后按 ID
排序，调用方列表顺序不参与集合身份；不隐式生成任何 order。空集合仅表示未声明要求，不是 vacuous VERIFIED。

`TriggerOrderRequirement` 带来源/架构、before_id/after_id 和精确 v1 kind：
`required_precedes` / `required_immediately_precedes`。端点只能是当前 spec steps，拒绝 state、悬空、
外部节点、自环、重复 edge，两种 order 合并后检查 DAG。该检查只是引用/结构一致性，**不是**完整约束求解。
Immediate 表达要求邻接，不表示 source lines 相邻或 runtime trace 已证实邻接，也不按 slot 自动推导。
SOURCE_SEQUENCE != REQUIRED_PRECEDES != RUNTIME_PRECEDES observation。

所有新 concrete trigger 模型（含 operands/constraints/source/requirements/orders/spec）使用各自
`v2-…-v1` namespace 与冻结 deterministic_id；完整规范化字段参与 ID，无时间、随机数或路径字段。
ID 为只读派生 property，不接受 caller-provided ID；JSON roundtrip 稳定，来源/slot/约束/显式顺序改变会
改变身份。冻结、tuple、嵌套 revalidation 保证 retained snapshot 不随 caller 输入修改；unchecked
model_copy/model_construct 不作为权威输入，重新 model_validate 时仍检查所有嵌套合同。

`tests/trigger/` 仅为 benign SYNTHETIC_FIXTURE，不是 ProcessorFuzz finding、真实硬件 trigger 或漏洞。
PF 绑定负例也只使用 synthetic provenance descriptors；未从真实 confirmed SI 或其 368 behavior records
构造 HardwareTriggerSpec。V2-5A 只读输出语义审计已完成；V2-5B 提取/缩减、matcher 和 reachability 均未实施。

## V2-5A.1 Confirmed Case Evidence IR（FROZEN）

V2-4 已冻结于 `chipchain-v2-4-stable` / `798d7ee99b4529a00007874c886c5ec8a39d0a28`。
V2-5A 审计完成但不证明 bundle provenance-complete：`out/tests/disassembly.asm` 的 348 个可比较
编码中 278 个与当前 ELF 不符，保持 quarantined；`note.log` 未绑定当前 SI；`transition.db`
混合/累积且缺少稳定 run identity。三者不进入本阶段 production adapter。

### 来源与 lossless 记录

公开合同位于 `chipchain.evidence`；解析 API 位于 `chipchain.adapters.hardware_case`：

- `parse_isa_csv(data: bytes, *, architecture, expected_sha256=None)`
- `parse_isa_log(data: bytes, *, architecture, expected_sha256=None)`
- `parse_rtl_log(data: bytes, *, architecture, expected_sha256=None)`
- `parse_signature(data: bytes, *, source_side, architecture, expected_sha256=None)`

全部返回 `ParsedCaseArtifact`，只消费调用者提供的单个 immutable bytes，不读路径、环境或调用后端。
`EvidenceArtifactSource` 保存 exact artifact_sha256、byte_length、architecture、source_side、format_profile_id，
来源 ID 是以上完整声明的版本化 hash。side 仅 ISA_SIDE/RTL_SIDE，不命名 truth；不含 hardware applicability。
四个 closed local profiles 为 `confirmed_isa_csv_v1`、`confirmed_isa_log_v1`、
`confirmed_rocket_rtl_log_v1`、`confirmed_signature_v1`，当前只支持显式 RISC-V。
profile 是本地受审计 print layout，不是上游版本/config 身份，也不是通用 ISA/RTL 格式承诺。

每个 observation 保存 source_id、零基 record_ordinal、kind、exact raw_line 和 FORMAT_OBSERVED。
规范 payload 只有一份：raw_line；PC/encoding/mode/state 等通过校验后的只读 property/method 提供，
不重复序列化另一套可独立修改的 typed fields。raw_line 不含行终止符；行终止符由 closed profile 指定。
record_ordinal 是 header 后的记录顺序（无 header 则从首行开始），不是 retirement ordinal 或 cycle。
同 PC/encoding 重复出现时因 ordinal 不同得到不同 ID；source SHA 变化也改变所有 record ID。

`ParsedCaseArtifact` 必须重新验证嵌套 source/observations、连续零基 ordinal、kind/profile/side/architecture，
然后重建 exact bytes（包括固定 header、CSV CRLF / 其他 LF、末尾终止符）并复核 SHA 和 byte length。
独立 observation 只证明局部格式与声明 source_id；完整 artifact 才建立 actual bytes 的来源绑定。
任意修改 raw、序列、来源或未校验的 model_copy 都不能绕过 detached validation。
byte_binding_level 固定 BYTE_VERIFIED，仅表示载荷字节一致，不认证来源真实性或 processor ground truth。
run_provenance 固定 CORRELATED_ARTIFACT_SET；没有 run_id/campaign_id/timestamp 或 authenticated-run 状态。

EvidenceLevel 独立词汇为 BYTE_VERIFIED、FORMAT_OBSERVED、PRODUCER_DECLARED、CROSS_ARTIFACT_CORRELATED、
INFERRED、UNKNOWN；它不是 BehaviorFactNature，词汇存在不表示本轮创建这些级别或自动升级。

### 局部格式与 typed views

| Profile | 记录与安全解释 |
| --- | --- |
| ISA CSV | 精确 17 列 header；64-bit printed PC、32-bit printed encoding；保留 mode 缺失、mixed gpr 更新及八个 state tokens；空 state 为 None |
| ISA log | DESCRIPTION / COMMIT / EXCEPTION / LABEL_OR_CONTEXT / OTHER_SUPPORTED（仅已观察 tval）；保留 exact lexical fields，不推断 post-state |
| RTL log | RTL_NORMAL / RTL_EXCEPTION / DELAYED 独立；40-bit printed PC、32-bit encoding；保留全部 print tokens，禁止把 DELAYED 归属猜测 PC |
| Signature | 恰好 254 条，每条 32 个小写 hex，零基 ordinal；不附 address、CSR 或 layout mapping；ISA/RTL side 独立 |

Instruction encoding 是打印的 hex token，不解码、不重排成指令 bytes，不证明 ISA 合法性。
CSV `gpr` 保留 mixed GPR/FPR/CSR 原文，不生成 register access/value facts。
RTL 的 COV 来自受审计 `io_covSum`，不是 cycle/time/retirement；WDATA 仅 raw token，deadbeef sentinel
不可当 architectural write。内部 FPR representation 不解释为 IEEE 值。
ISA log 的 description state vector 九个 token 保留词法，第九项不命名为已证实 CSR。
内部 RTL fields 除显式共同字段外只作 lossless token 保留，不默认与 ISA 状态比较。

### 对齐与字段比较

`AlignmentScope` 保存双方完整 source descriptors（因此有 ID/SHA）、显式 common_start_pc、
固定 `confirmed_common_sequence_v1` 和 nonempty/duplicate-free/canonical ordered comparable_fields。
唯一允许的字段依次为：mstatus、frm、fflags、mcause、scause、medeleg、mcounteren、scounteren；
比较位宽依次为 64、3、5、8、8、64、32、32，表示双方被批准比较的 printed view，非完整寄存器集合。

`align_common_program(scope, isa_artifact, rtl_artifact)` detached revalidate 全部输入，要求 ISA CSV
从显式 common start 开始，RTL instruction records 中 start key 唯一，随后与全部 ISA records
逐对 PC + encoding 相同且连续。只使用 common-program file order + PC + encoding，不使用 COV、
文本相似度、物理行号相等、动态规划或插删猜配；歧义/断裂/缺失直接 fail closed。
DELAYED 不参与 instruction-key 序列，但仍列入未配对记录；boot/tail 不丢弃。

`AlignedPair` 保留 scope、零基 alignment_ordinal、双方 observation（ID 可恢复）、PC/encoding 和 comparisons。
`AlignmentResult` 保存完整双方 artifacts、有序 pairs、双方未配对 IDs，固定状态
RELIABLE_KEYS_PARTIAL_SEMANTICS。验证器重新执行序列选择、检查 pair 完整成员身份/顺序与 comparisons，
拒绝篡改、不完整结果和虚构来源；不生成任何 verification record。

`FieldComparison` 包含 field、isa_value/rtl_value（公开 ExactScalar 或 None）、outcome、可选 xor。
outcome 为 EQUAL / DIFFERENT / NOT_COMPARABLE / MISSING_LEFT / MISSING_RIGHT。
双方缺失或宽度不同为 NOT_COMPARABLE；单边缺失保留 MISSING_*；等宽不同值保存描述性 XOR。
模型重算 outcome/XOR，pair 再从 raw 来源重算批准字段，不能仅提交 caller-claimed DIFFERENT。
`DivergenceObservation` 只绑定 aligned_pair + field，scope、精确值/XOR 从 pair.comparison 可恢复，
级别固定 CROSS_ARTIFACT_CORRELATED，无 causal/trigger/necessary/sufficient/verified/vulnerability 字段。

`first_observed_divergence_in_scope(result)` 是该范围/有序 pairs 中首个 DIFFERENT，非 global first error。
`divergence_context(result, observation, before=5, after=3)` 只返回邻近 aligned pairs；不标记 critical 指令、
不构造 trigger window/causal slice。真实审计支持 293-key common alignment，首差异前的指令不被声称 causal。
CSV/log 293-key correspondence 仅保留本地 acceptance correlation，不称 CSV 由 log 生成的 provenance 证明。

所有合同 frozen + tuple + nested revalidation；完整规范化 payload 使用 `v2-…-v1` ID namespace，
不含 path/time/random。公开 ingestion 和 alignment 入口重新验证输入；unchecked 对象不能当可信结果。
`tests/evidence/` 仅使用 benign synthetic format-only fixtures，无真实指令序列或差异值。
真实 case 仅在默认 tests 通过后本地只读验收，不成为默认测试依赖或已认证漏洞 fixture。
V2-5A.1 冻结于 `chipchain-v2-5a1-stable` / `677f3228488f0f567cdf223850955530b8c546d4`；
V2-5A.2 hardware-test anchor binding 为 CURRENT，V2-5B LLM-assisted extraction/reduction 未实现；
当前没有 runtime ProcessorBehaviorFragment projection、真实 HardwareTriggerSpec、LLM、firmware 分析或 simulator 执行。

## V2-5A.2 Hardware-Test SI / ELF / Trace Anchors（CURRENT，待审查）

当前 `hardware_buginfo/testis/out/tests/.input_1.elf` 是硬件实验 testcase/test-program ELF，
不是 client/deployed/GDBFuzz firmware，也不是固件团队 artifact。`HardwareTestProgramELFSource`
的 artifact_kind 固定 HARDWARE_TEST_PROGRAM_ELF，不包含 ImmutableFirmwareArtifact/client binding。
项目尚未接入固件团队材料。本阶段只建立硬件侧来源相关关系，不建立 client firmware → hardware trigger。

### ELF view 与 exact byte consumption

公开入口 `chipchain.anchors.parse_hardware_test_elf(data: bytes, *, expected_sha256=None)`。
固定 `confirmed_riscv_elf64_le_v1`：ELF64、little endian、RISC-V、ET_EXEC、普通 program/section
table numbering、静态 symtab/strtab；不支持 extended indices 或通用 ELF framework。
只用 stdlib struct，不读文件、不执行 readelf/objdump/模拟器，不依赖 disassembly.asm。

source 保存实际消费 bytes 的 SHA/length、RISC-V 与 local profile。view 保存 entry virtual address、
PT_LOAD file offset/virtual address/file size/memory size/flags/alignment、section metadata 与 symtab records。
symbol 保存 exact name/value、type/binding/other、section index、table/record ordinal；不从名称推断语言语义。
非法范围、截断、整型越界、错误 string/symbol table、未知 local profile 均 fail closed。
ELF section 名称只是词法 metadata；本阶段不解析 `.riscv.attributes` 内容或据此补全硬件 ISA profile。

view 不嵌入整个 ELF binary。`revalidate_hardware_test_elf(view, data)` 重新解析同一 exact bytes，
要求 SHA/length 与完整 parsed view 一致；结构上合法的 caller-mutated view 仍不足以创建 anchor。
`read_elf_file_backed_bytes(view, data, *, address, size)` 先执行上述复核，只接受唯一 LOAD 的完整
file-backed interval。拒绝 BSS、无 mapping、跨界及任何竞争 LOAD overlap（含另一 LOAD 的 BSS）。
不把 virtual address 当 physical/MMIO/client firmware address，不把零填充当文件数据。

### 三类 anchor 与 source-backed 服务

- `anchor_si_label(raw_si, elf, elf_bytes, *, si_record_id, behavior_fragment=None)`：重新验证完整 raw SI
  snapshot 和 ELF；仅允许该 raw SI 中显式带标签的 record，与唯一同名且位于其 allocated section 的
  defined symbol 匹配。无匹配抛 MissingSymbolError，多 occurrence 抛 AmbiguousSymbolError；不默默挑选。
- `anchor_trace_instruction(elf, elf_bytes, trace_artifact, *, observation_id)`：重新验证完整 trace 来源与
  occurrence membership，当前只接受 confirmed ISA CSV 或 RTL NORMAL/EXCEPTION。按固定
  `confirmed_riscv_trace_word32_le_v1` 将 8-hex textual word 转为四字节 little-endian，与 exact ELF
  file bytes 比较；拒绝 compressed/long instruction-width markers、错误编码、DELAYED 和其他 profile。
- `compose_hardware_case_anchor(si_anchor, trace_anchor, *, raw_si, elf, elf_bytes, trace_artifact,
  behavior_fragment=None)`：重新消费全部 sources 并再现两侧 anchor；要求所有字段一致、same exact ELF
  source、trace PC == symbol address。不同 trace source、occurrence、SI SHA 或 altered declaration 均拒绝。

持久化 SILabelELFAnchor 保存 SI snapshot ID/SHA、raw record、ELF source、symbol，以及 optional behavior reference。
ELFTraceInstructionAnchor 保存 ELF source、trace source、完整 observation 与四字节 file hex。
HardwareCaseInstructionAnchor 组合两侧 immutable snapshots。source side/PC/encoding/ordinal/IDs 均可从保留
字段精确恢复，evidence level 固定 CROSS_ARTIFACT_CORRELATED，无 causal/trigger/critical/verified 字段。
这些模型反序列化仅检查声明内部一致性，不能认证未提供的 ELF bytes；消费/组合必须走上述 source-backed APIs。

optional ProcessorBehaviorAnchorBinding 只接受 supplied PROCESSORFUZZ_SI fragment：冻结 mapper 重新生成
SOURCE_DECLARED projection，要求完整 fragment 相等，核对 SHA/context、RISC-V、source ordinal 与成员身份。
不重解释 operands，不新增 access/state/event，也不把 ELF 地址写回冻结 InstructionBehavior。

### 部分性与科研边界

label anchor 只属于携带该 label 的 SI record。203 个标签存在不等于 368 条 SI 指令完成编译映射；
未标记指令、缺失标签和歧义项不产生地址，不按 ordinal/相邻记录/固定步长/标签编号/下一 symbol 推算。
重复 PC/encoding 的不同 trace occurrence 仍有不同 anchor ID。所有 ID 使用完整版本化 canonical payload，
无 path/time/random；tuple/frozen 与 detached source revalidation 保持输入隔离。
Byte Match != Build Provenance；Symbol Match != Compilation Proof；Trace PC/Encoding Match != Causality。
硬件 testcase ELF 与 client firmware 不是同一程序/目标；本阶段没有 firmware reachability 或跨层候选。
stale disassembly、note.log、transition.db 均不消费；不读取 `.S` 来猜测编译映射，不提取/缩减 trigger。
永久 tests 仅使用手工构造 benign synthetic ELF/SI/trace；真实案例只在 tests 通过后只读验收。

本地只读验收：368 条 SI instructions 中 208 条携带标签，203 个 unique label anchors；
`_s0`–`_s4` 保持缺失，无 ambiguous label。ISA CSV 293 条全部 byte-anchor；RTL 的 326 条
instruction records 中 321 条 byte-anchor，5 条启动 PC 无 ELF LOAD mapping，34 条 DELAYED 单独保留。
exact symbol address == trace PC 的 composed anchors 每侧仅 10 个，不扩大成全 SI 编译映射。
首个 scoped divergence 的两侧观察可独立绑定同一 ELF bytes，但该 PC 无 SI label anchor，不能反推 SI 指令。
未出现在采样 trace 同地址集合的标签不等于对应指令未执行；不据此解释 branch/path/causality。
