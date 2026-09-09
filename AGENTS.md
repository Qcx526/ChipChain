# ChipChain V2 开发约束

## 当前方向

- 当前主线为 `v2-mainline`；当前阶段 V2-R0 只包含最小 core 与 CLI shell。
- RISC-V 是主实验架构，RISC-V-first != RISC-V-only。ARM 等后续能力通过独立 profiles/adapters/backends 实现。
- 架构词汇不代表 backend 已完成；不得跨架构拼接事实或攻击链。
- 未来硬件侧来源：ProcessorFuzz → RISC-V SI → Hardware Trigger。
- 未来固件侧来源：GDBFuzz → 原始不可变 firmware 的 external-input fuzzing → firmware behavior artifact。
- ChipChain 的未来核心是 Processor Behavior + Trigger Extraction + Trigger Matching + Reachability。
- R0 不实现 Processor Behavior IR、SI/GDBFuzz adapter、Trigger IR、decoder、matcher、reachability 或 verification。
  下一步依照 [PLANS.md](PLANS.md) 独立授权。

## 目标与科研边界

- 项目仅用于防御性科研；使用自有、公开、synthetic 或明确授权来源，准确标明来源性质。
- 固定 client hardware + 不可变 original firmware 定义真实目标；允许分析 byte-identical 离线副本。
- 不得以 patch、recompile、instruction insertion、JTAG code injection 或修改程序字节的 software breakpoint
  制造原始目标证据。Modified Firmware != Evidence For Original Firmware；Different Firmware SHA != Same Target。
- Injected State != Naturally Reached State；JTAG Observation != Firmware Modification。
- 确定性、可复核事实优先于 LLM 创作。LLM 只做未来 coordinator/reasoner，knowledge 只提供上下文。
- 不虚构 vulnerability、verification 或 attack-chain verdict；静态存在、匹配候选、来源 SHA 都不证明漏洞。
- Type II 不发明 initiating software vulnerability；Type III 不反转软件→硬件路径冒充因果证据。
- 遵循 [科学边界](docs/SCIENTIFIC_BOUNDARIES.md)，保留所有未知项与来源范围。

## 工程与检查

- Ubuntu 是 canonical 开发环境；Python >= 3.11、src layout，公共 API 提供类型标注与必要 docstring。
- 先检查 Git 状态与相关文档，保护已有改动；小型、单职责模块，拒绝多余字段和隐式全局状态。
- V2 身份仅由显式 namespace 与 canonical JSON/SHA-256 生成，不生成 wall-clock/random identity。
- 冻结模型使用不可变字段类型；嵌套输入需重新验证，不能仅依赖浅层 frozen 标志。
- core、root、CLI 不依赖业务子系统或分析/运行/模型后端，不留下未来模块空壳。
- 默认测试离线，无 API Key、数据库、QEMU/JTAG 或网络依赖；`.env` 不提交、不自动加载。
- 每阶段按 Plan → Implement → Test → Review → Fix → Document 完成；如实记录验证结果。
- 完成后运行完整 pytest、compileall、两种 CLI help 与 `git diff --check`，同步相关文档。

## Git 与归档

- `archive/phase10-foundation` 是只读历史基础，`phase-10-foundation-final` 固定同一完整历史提交。
- 历史源码可通过 `git show archive/phase10-foundation:<path>` 审阅；按后续合同选择迁移，不恢复全套旧依赖。
- 不移动 main、archive 或现有 tags；保持连续 Git 历史，禁止 orphan/history rewrite。
- 未获明确验收和操作授权，不 commit、不 push、不创建或移动 tag。默认保留修改为 unstaged。
