# Role-Aware Cross-Layer Localization

位置分为 initiating_root_cause、cross_layer_trigger_point 与 affected_execution_point。
Phase 9A-R 不再把三个角色压成单一 RootCause。

当前 Type II ARM 只在显式 trigger binding 指向已验证 MMIO edge 时定位
cross_layer_trigger_point。Program/function/instruction 使用 ProgramAddress，MMIO register
使用 HardwareAddress；MMIO site 不会升级为 initiating root cause。

Localizer 只解析 Behavior verifier 给出的 `supporting_evidence_ids`。仅 resolved/inspected、
未通过 relation contract 的 Evidence 不得提供 instruction、source 或 location。

只有 Evidence 明确含真实 source_file/source_line 才填写源码位置；instruction count、byte
distance 或 assembly line 不得冒充 source-line error。KG hint 与 Agent recommendation 不能
直接成为 location truth。Type III 无反向 Evidence 时不产生 verified localization。
