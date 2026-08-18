# 行为图与漏洞知识图的实体链接契约

## 当前状态

Phase 5 只定义可审计的精确匹配键，不执行实体链接，不生成跨图 Edge，也不搜索
候选攻击链。行为图和漏洞知识图分别保存、分别加载，并使用不同的节点、关系和
JSON 快照格式。

## 为什么 Node ID 不能直接相等

`BehaviorNode.id` 标识一次具体程序分析中的实体，通常包含 artifact 或 analyzer
上下文。`KnowledgeNode.id` 标识一个漏洞样本中的语义实体，除 CWE/CAPEC 外还
包含 sample 上下文。二者生命周期、来源和去重规则不同，因此 Node ID 不得被
当作跨图连接条件。

例如 Phase 4B 行为硬件节点为：

```text
synthetic-arm-mmio:memory-map:synthetic-arm-mmio-map:region:fixture-mmio-register
```

Phase 5 对应知识节点为：

```text
hardware-resource:arm:FIXTURE-ARM-KG-001:fixture-mmio-register
```

这两个 ID 有意不同。

## Canonical Match Keys

匹配键只能由结构化、可复核字段确定性产生，不使用名称模糊匹配：

| 实体 | 键格式 | ARM fixture 示例 |
| --- | --- | --- |
| 硬件地址 | `arch:<arch>:address:<canonical-hex>` | `arch:arm:address:0x40000000` |
| Memory Map region | `arch:<arch>:mmio-map:<map-id>:region:<region-id>` | `arch:arm:mmio-map:synthetic-arm-mmio-map:region:fixture-mmio-register` |
| Component | `arch:<arch>:component:<component-id>` | `arch:arm:component:fixture-driver-component` |
| Interface | `arch:<arch>:interface:<kind>:<identifier>` | `arch:arm:interface:ioctl:fixture-ioctl-0x41` |

地址键只接受十六进制字符串并规范为 Python `hex()` 形式；符号地址不产生该键。
Memory Map 键只在
`memory_map_id` 和 `memory_map_region` 同时存在时生成。Interface 没有结构化
identifier 时不生成该键。缺字段或字段格式不支持时保持无匹配，不从 label/name
猜测。

## Phase 4B 硬件锚点

自有 fixture 的 `MemoryRegion`、Behavior Hardware Node 和 VulnerabilitySample
HardwareResource 都明确指向 `0x40000000`、`synthetic-arm-mmio-map` 和
`fixture-mmio-register`。两张图独立调用同一 canonical key helper，测试要求结果
完全相等。`resource_kind=register` 的 MemoryRegion 还必须满足 `start == end`，
避免用一个范围冒充单个寄存器。

## Phase 6 可采用的保守链接步骤

1. 先强制 architecture 相等；全局 CWE/CAPEC 不作为硬件链接端点。
2. 对两边 canonical key 集合求交，只接受结构化键的精确相等。
3. 为每个链接结果保留两端 Node ID、相交键、来源和证据引用。
4. 多候选、键冲突或字段缺失时返回未链接/歧义，不使用名称猜测补全。
5. 链接结果应是独立的候选映射数据，不回写或覆盖任一源图节点。

这些步骤是 Phase 6 建议，不属于当前实现。
