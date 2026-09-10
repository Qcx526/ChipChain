# ChipChain V2 开发约束

## 当前方向

- 当前主线为 `v2-mainline`；V2-R0/V2-1/V2-2 已冻结，V2-2 仅有 behavior.processor 数据合同，CLI 仍是 shell。
- RISC-V 是主实验架构，RISC-V-first != RISC-V-only。ARM 等后续能力通过独立 profiles/adapters/backends 实现。
- 架构词汇不代表 backend 已完成；不得跨架构拼接事实或攻击链。
- 未来硬件侧来源：ProcessorFuzz → RISC-V SI → Hardware Trigger。
- 未来固件侧来源：GDBFuzz → 原始不可变 firmware 的 external-input fuzzing → firmware behavior artifact。
- ChipChain 的未来核心是 Processor Behavior + Trigger Extraction + Trigger Matching + Reachability。
- V2-2 冻结层只有 Processor Behavior IR 合同；独立 SI structural parser/mapper 不承担 trigger 提取。
  trigger 层仅定义规范性要求，不实现 GDBFuzz adapter、decoder、matcher、reachability 或 verification。
  下一步依照 [PLANS.md](PLANS.md) 独立授权。

## 目标与科研边界

- 项目仅用于防御性科研；使用自有、公开、synthetic 或明确授权来源，准确标明来源性质。
- 固定 client hardware + 不可变 original firmware 定义真实目标；允许分析 byte-identical 离线副本。
- 不得以 patch、recompile、instruction insertion、JTAG code injection 或修改程序字节的 software breakpoint
  制造原始目标证据。Modified Firmware != Evidence For Original Firmware；Different Firmware SHA != Same Target。
- Injected State != Naturally Reached State；JTAG Observation != Firmware Modification。
- GDBFuzz SUTConnection 是 host-side delivery，不是 firmware API；host adapter 必须匹配客户既有协议，
  不得以 bundled serial example 为理由修改原始固件加 harness。Transport 不等于 application protocol。
- 相同架构/model 不证明硬件目标相等；ProcessorFuzz target 不自动适用于 client。来源只能绑定显式固件
  ID/SHA/架构/目标快照；镜像不可变不证明 halt/step/reset 等调试操作没有扰动自然运行。
- 确定性、可复核事实优先于 LLM 创作。LLM 只做未来 coordinator/reasoner，knowledge 只提供上下文。
- 不虚构 vulnerability、verification 或 attack-chain verdict；静态存在、匹配候选、来源 SHA 都不证明漏洞。
- Type II 不发明 initiating software vulnerability；Type III 不反转软件→硬件路径冒充因果证据。
- Processor Behavior 必须显式区分 SOURCE_DECLARED、STATIC_DECODED、STATIC_INFERRED、RUNTIME_OBSERVED、
  SYNTHETIC_FIXTURE。SOURCE_SEQUENCE、STATIC_CFG_SUCCESSOR、依赖关系和 RUNTIME_PRECEDES 不互相升级。
  Register access 不是 value observation；未知不是零；Behavior IR 不是 Trigger IR 或 vulnerability。
- Source context 绑定 provenance/target，不统一规定 fact nature；同一固件 context 可含 STATIC_DECODED
  指令与 STATIC_INFERRED 关系，但不能混入不同来源/目标。InstructionBehavior 不是 runtime occurrence；
  RUNTIME_PRECEDES 只连接显式 ProcessorEvent occurrences，运行顺序不代表因果。
- 遵循 [科学边界](docs/SCIENTIFIC_BOUNDARIES.md)，保留所有未知项与来源范围。

## 工程与检查

- Ubuntu 是 canonical 开发环境；Python >= 3.11、src layout，公共 API 提供类型标注与必要 docstring。
- 先检查 Git 状态与相关文档，保护已有改动；小型、单职责模块，拒绝多余字段和隐式全局状态。
- V2 身份仅由显式 namespace 与 canonical JSON/SHA-256 生成，不生成 wall-clock/random identity。
- 冻结模型使用不可变字段类型；嵌套输入需重新验证，不能仅依赖浅层 frozen 标志。
- core、root、CLI 不依赖业务子系统或分析/运行/模型后端，不留下未来模块空壳。
- behavior 只能依赖 stdlib/Pydantic/core/behavior；core 不反向依赖 behavior，IR 不依赖未来 adapters/backends。
- SI adapters 只能依赖 stdlib/Pydantic/core/behavior/自身模块；core/behavior/root/CLI 不反向导入 adapters。
  SI parser 消费 exact bytes，mapper 必须 detached revalidate 并匹配 ProcessorFuzzArtifact SHA；
  只生成 SOURCE_DECLARED 指令与 SOURCE_SEQUENCE，不能推断状态、访问效果或运行事件。
- evidence 只能依赖 stdlib/Pydantic/core、公开 behavior 值类型及自身模块；hardware_case adapters
  只能依赖 stdlib/Pydantic/core/evidence/自身模块，不读取文件或执行后端。
  core/behavior/trigger/root/CLI 与冻结 SI adapter 不反向依赖 evidence；不复用 BehaviorFactNature。
  字节绑定只证明 exact payload 一致，不能认证 run/producer；raw 与 typed views 必须一致，未知保持未知。
  COV 不是 time/cycle，WDATA sentinel 不是 architectural write，DELAYED 独立保留。
  非因果对齐只比较显式批准字段，首个差异始终限于 scope；不把差异/上下文变成 trigger/root cause。
- trigger 只能依赖 stdlib/Pydantic、公开 core/behavior 合同及自身模块；不导入 behavior 私有 helper
  或 adapters/backends，core/behavior/adapters/root/CLI 不反向导入 trigger。
- Trigger requirement != Processor Behavior fact != requirement satisfaction；不复用 BehaviorFactNature。
  requirement_slot 只是局部节点身份，不是 source/runtime ordinal；集合次序不隐含执行顺序。
  SOURCE_SEQUENCE 不自动升级为 REQUIRED_PRECEDES；规范性邻接不是观察结果。
  来源绑定不证明要求正确、最小、已触发或适用于 client；提取/缩减与满足性判断需独立授权。
- 项目负责人声明的 Rocket/ProcessorFuzz family 不证明具体配置或版本；显式 unspecified local ID
  不是上游 profile，也不是 authenticated provenance，未知 revision/ISA profile 必须保持未知。
- hardware-test ELF 是 ProcessorFuzz/ISA/RTL 硬件实验 artifact，不得绑定为 ImmutableFirmwareArtifact
  或冒充 client/固件团队输入；hardware-test 地址/执行/差异不证明 client firmware reachability 或跨层漏洞。
  anchors 可单向消费公开 core/behavior/evidence/ProcessorFuzz adapter；下层不能反向依赖 anchors。
  anchor 服务必须复现 exact ELF bytes/view 并重新验证 SI/trace 来源，symbol match 不是 compilation proof。
  SI label anchor 仅属于携带该标签的记录；不得向无标签邻居推算地址。
- candidates 可单向消费公开 core/behavior/evidence/anchors/trigger；所有冻结下层及 root/CLI 不反向依赖它。
  唯一批准的直接 adapter 例外：仅 context builder 可导入
  `chipchain.adapters.processorfuzz.models.RawProcessorFuzzSI` 数据合同，为冻结 anchor 服务提供 exact-source
  重建输入。不得直接导入/调用 SI parser、mapper 或其他 adapter，不在 anchors 重导出数据合同。
  context 只产生 bounded compact facts 与未解决项，不自动生成要求；typed refs 必须绑定 kind/ID/owner。
  候选固定 HYPOTHESIS；proposed requirements 不是 satisfied requirements，rationale 不是 objective evidence。
  缺失 SI anchor、未认证 run/build、因果与必要/充分性未知不能因引用校验成功而消失。
- 默认测试离线，无 API Key、数据库、QEMU/JTAG 或网络依赖；`.env` 不提交、不自动加载。
- 每阶段按 Plan → Implement → Test → Review → Fix → Document 完成；如实记录验证结果。
- 完成后运行完整 pytest、compileall、两种 CLI help 与 `git diff --check`，同步相关文档。

## Git 与归档

- 仓库根目录 `/hardware_buginfo/`、`/hardware_caseinfo/` 保留为 `LOCAL_ONLY_REAL_ARTIFACT`；
  后者是完整 Hardware Case Bundle 的首选名称，但不得自动移动、改写或重命名真实材料。
  默认不提交 SI、trace、signature 或 build artifacts，不使用 `git add -f` 绕过隔离。
  Hardware-team-confirmed valid SI testcase 只是外部来源确认，不等于 ChipChain verification。
- `archive/phase10-foundation` 是只读历史基础，`phase-10-foundation-final` 固定同一完整历史提交。
- 历史源码可通过 `git show archive/phase10-foundation:<path>` 审阅；按后续合同选择迁移，不恢复全套旧依赖。
- 不移动 main、archive 或现有 tags；保持连续 Git 历史，禁止 orphan/history rewrite。
- 未获明确验收和操作授权，不 commit、不 push、不创建或移动 tag。默认保留修改为 unstaged。
