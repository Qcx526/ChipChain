# V2-R0 数据合同

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
