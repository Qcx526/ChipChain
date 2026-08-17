# 数据模型当前实现说明

## 实现状态

Phase 1 已使用 Pydantic v2 实现 ChipChain 的第一版领域数据契约。模型位于 `src/chipchain/models/`，不依赖 NetworkX、Neo4j、程序分析器或 LLM SDK。

模型层允许 ARM、RISC-V、PowerPC、SPARC 和 LoongArch 数据独立存在。当前只实现 ARM MVP 是 Pipeline / Search 层的限制；领域模型不会永久禁止未来架构。与此同时，单条 `AttackChain` 和单个 `VulnerabilitySample` 内的架构专有实体必须保持一致。

## 公共约定

- JSON 字段使用 snake_case，枚举序列化为稳定的小写字符串。
- 所有模型继承 `DomainModel`，默认 `extra="forbid"`，字段拼写错误不会被静默忽略。
- ID 和必要文本不能为空，输入两端空白会被移除。
- 所有 confidence、score、score component 和 evidence coverage 都限制在 `[0, 1]`。
- 列表和字典使用 `default_factory`，实例之间不共享可变默认值。
- metadata 只允许 JSON 可序列化值。
- 地址使用非空字符串，可保存 `0x401020`、地址范围或符号地址；Phase 1 不对未来地址形式做过度限制。
- `created_at` 必须是 timezone-aware datetime，默认使用 UTC。

## 模块划分

| 模块 | 当前模型 |
| --- | --- |
| `enums.py` | Architecture、Layer、SampleType、EvidenceType、BehaviorType、NodeKind、RelationType、ChainStatus、EdgeVerificationStatus |
| `evidence.py` | Evidence |
| `behavior.py` | Behavior、Interface |
| `hardware.py` | HardwareResource、SecurityMechanism、Impact、RootCause |
| `vulnerability.py` | Component、Trigger、Precondition、VulnerabilitySample |
| `graph.py` | BehaviorNode、BehaviorEdge |
| `chain.py` | AttackChainNode、AttackChainEdge、AttackChain |

公共模型从 `chipchain.models` 导出，调用者无需依赖内部文件布局。

## 稳定枚举

- Architecture：`arm`、`risc_v`、`powerpc`、`sparc`、`loongarch`
- Layer：`firmware`、`driver`、`architecture`、`hardware`、`interface`、`impact`
- SampleType：`real`、`synthetic`、`demo`、`fixture`
- EvidenceType：`knowledge_graph`、`static_analysis`、`dynamic_analysis`、`architecture_rule`、`source_reference`、`llm_semantic`
- ChainStatus：`candidate`、`partially_verified`、`verified`、`rejected`
- EdgeVerificationStatus：`unverified`、`verified`、`rejected`
- BehaviorType：`call`、`syscall`、`ioctl`、`mmio_read`、`mmio_write`、`register_access`、`dma_read`、`dma_write`、`interrupt`、`privilege_transition`、`data_flow`
- NodeKind：`vulnerability`、`function`、`driver_function`、`interface`、`register`、`hardware_resource`、`security_mechanism`、`weakness`、`impact`
- RelationType：`calls`、`invokes`、`issues`、`data_flows_to`、`mmio_read`、`mmio_write`、`accesses`、`triggers`、`exploits`、`leads_to`

## Evidence

`Evidence` 保存证据 ID、类型、来源、artifact、地址、指令、规则 ID、置信度、验证标记、引用和 metadata。行为事实与证据保持分离：例如 `mmio_write` 属于 Behavior/Edge，观察到该写操作的指令和位置属于 Evidence。

Evidence 本身不判断程序分析结果是否真实；它只保证数据完整、可引用和可序列化。

## VulnerabilitySample

`VulnerabilitySample` 聚合：

- CVE/CWE/CAPEC 标识；
- Component、Trigger、Precondition；
- Behavior 和 Interface；
- HardwareResource 和 SecurityMechanism；
- Impact、Evidence 和 RootCause；
- sample type、来源、引用和验证状态。

当前跨字段校验：

1. `sample_type=real` 时，`source` 或 `references` 至少一个非空。
2. Component、Behavior、Interface、HardwareResource、SecurityMechanism 和 RootCause 的 architecture 必须与样本一致。
3. Evidence ID 在样本内唯一。
4. Trigger、Precondition、Behavior、Interface 和 RootCause 引用的 Evidence ID 必须存在于样本的 Evidence 目录。

fixture、demo 和 synthetic 不会被自动赋予 CVE 或真实来源。仓库 fixture 使用 `FIXTURE-*` 和 `chipchain-test-fixture` 明确标识。

## Behavior Graph 数据契约

`BehaviorNode` 使用稳定 ID、NodeKind、Architecture 和 Layer，可直接通过 `model_dump(mode="json")` 转换成当前 GraphRepository 后端需要的属性字典。

`BehaviorEdge` 使用 `source_id` / `target_id` 引用节点，以 RelationType 限定核心关系，并通过 Evidence ID 引用证据。Phase 1 模型本身不检查节点是否存在；Phase 2 GraphRepository 在插入和加载时负责端点、全局 Edge ID 和架构一致性验证。

## 线性 AttackChain

第一版仅支持 linear chain，不支持 DAG 或分支攻击图。

`AttackChainNode` 是底层实体的有序视图，包含 `entity_id`、`order`、`kind`、`architecture`、`layer` 和 `label`。`AttackChainEdge` 连接相邻实体，并使用三态 `verification_status` 区分尚未验证、验证成功和验证失败。

`AttackChain` 内嵌 Evidence 目录，Edge 和 RootCause 通过 ID 引用。这使单个 JSON 自包含，也允许模型检查 verified chain 的最低证据条件。

当前跨字段校验：

1. 至少存在一个节点。
2. 节点按列表顺序形成从 0 开始的连续 order，且 entity ID 唯一。
3. `len(edges) == len(nodes) - 1`。
4. 第 i 条 Edge 必须连接第 i 和第 i+1 个节点。
5. Node、Edge 和 RootCause architecture 必须与 Chain architecture 相同。
6. Edge ID 和 Evidence ID 在链内唯一，Evidence 引用不得悬空。
7. `status=verified` 时每条 Edge 必须为 verified，必须引用 Evidence，且至少包含一条 `verified=true` 的非 `llm_semantic` Evidence。
8. score、score components 和 evidence coverage 必须在 `[0, 1]`。
9. `created_at` 必须携带时区。

第 7 条只是最低结构/类型门槛，不替代 Phase 7 的真实性、架构规则和动态证据验证算法。

## RootCause 的 register 字段

Pydantic 新版本的 BaseModel 已有同名属性。为避免字段遮蔽警告，Python 内部字段名为 `register_name`，外部 JSON 始终使用需求规定的 `register`；`root_cause.register` 只读属性仍可访问该值。其他 RootCause 定位字段包括 function、binary address、instruction、MMIO address、hardware resource 和 security mechanism。

## JSON 与 Schema

加载和 round-trip：

```python
chain = AttackChain.model_validate_json(json_text)
json_text = chain.model_dump_json(indent=2)
```

运行：

```powershell
python scripts/export_schema.py
```

会生成 `VulnerabilitySample` 与 `AttackChain` 的 JSON Schema 到 `artifacts/schema/`。该目录已被 Git 忽略：模型代码是唯一来源，生成文件可随时重建，因此不提交重复副本。

## 当前边界

模型只负责结构和明确的领域不变量，不执行图查询、候选攻击链推理、静态/动态分析或证据真实性判断。Phase 2 GraphRepository 直接消费 Node/Edge 的 JSON 字典并返回独立 GraphPath；后续 Candidate Search 可以使用这些结构路径组装完整线性链再统一校验，Verifier 可以更新逐边状态后重新构造并校验 AttackChain。
