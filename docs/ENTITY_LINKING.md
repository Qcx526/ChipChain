# 行为图与漏洞知识图的实体链接契约

## 当前状态

Phase 6 已实现 Hardware Anchor 的精确实体链接。行为图和漏洞知识图仍分别保存、
分别加载，并使用不同的节点、关系和 JSON 快照格式；链接结果是独立 `EntityLink`
对象，不是跨图 Edge，也不会写回任一 Repository。

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

## Phase 6 精确链接步骤

1. 先强制 architecture 相等；全局 CWE/CAPEC 不作为硬件链接端点。
2. 对两边 canonical key 集合求交，只接受结构化键的精确相等。
3. 为每个链接结果保留两端 Node ID、相交键、link method 和审计 metadata。
4. 一个 Behavior Hardware Node 可链接多个 Knowledge HardwareResource，每个精确
   匹配都保留，不把 one-to-many 当作歧义。
5. 字段缺失或无交集时记录 unmatched，不使用名称、编辑距离、embedding 或 LLM
   猜测补全。
6. Link ID 由 architecture 和两端 Node ID 的稳定 SHA-256 摘要产生。
7. 链接结果应是独立的候选映射数据，不回写或覆盖任一源图节点。

第一版只支持 Behavior Register/HardwareResource 到 Knowledge HardwareResource。
Component/Interface 虽已有 match key contract，但尚未加入 Linker。

## EntityLink 的有限语义

`EntityLink` 只说明两端实体具有至少一个完全相同的 canonical identity anchor。
它不说明漏洞存在、Trigger/Precondition 已满足、行为能够利用漏洞或攻击链已验证。
Phase 6 Candidate Search 如何消费链接结果见 `CANDIDATE_SEARCH.md`。
