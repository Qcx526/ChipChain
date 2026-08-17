# angr 接入说明（Phase 4A 已实现）

## 状态与边界

Phase 4A 已实现 ARM ELF 的真实静态分析最小闭环：

```text
ARM ELF → AngrAnalyzer → ProgramAnalysisResult
        → ingest_analysis_result → GraphRepository → GraphPath
```

适配器只恢复可观察的函数与调用事实，不输出 CVE、CWE、Hardware
Weakness、Exploitability、Privilege Escalation 或 AttackChain。Phase 4A 未实现
MMIO、数据流、污点、符号执行和漏洞检测。

## 已验证环境

验证日期：2026-08-17。

| 项目 | 实测值 |
|---|---|
| OS | Windows x86-64 |
| Python | 3.14.6 |
| pip | 26.1.2 |
| angr | 9.3.2 |
| ARM compiler | 未安装 |
| Project smoke test | 通过 |
| CFGFast smoke test | 通过 |

PyPI 的 angr 9.3.2 metadata 声明 Python `>=3.12`、列出 Python 3.14，
并提供 CPython 3.12+ ABI3 Windows x86-64 wheel：
<https://pypi.org/project/angr/9.3.2/>。安装遵循官方建议，在仓库 `.venv`
隔离环境中完成：<https://docs.angr.io/en/stable/getting-started/installing.html>。

实际执行：

```powershell
.\.venv\Scripts\python -m pip install "angr==9.3.2"
.\.venv\Scripts\python -c "import angr; print(angr.__version__)"
```

安装日志保存在本地忽略目录 `artifacts/phase4/angr-install.log`。导入时 angr
报告 `unicornlib.dll` 不可用；Unicorn 是可选执行加速路径，本阶段只使用静态
`CFGFast`，Project 与 CFG 冒烟及全部集成测试均通过。

## 可选依赖

angr 不属于基础依赖或 `dev` extra：

```powershell
pip install -e ".[dev]"       # Phase 0～3 与非 angr 测试
pip install -e ".[dev,angr]"  # Phase 4A 集成测试和 Demo
```

`chipchain.analysis` 可以在未安装 angr 时导入。`AngrAnalyzer` 只在执行
`analyze()` 时动态导入后端，并以稳定的 `ProgramAnalysisError` 说明缺失
extra。angr 集成测试带 `angr` marker 和 import skip。

## AngrAnalyzer 契约

公共契约保持不变：

```python
AngrAnalyzer(ProgramAnalyzer).analyze(
    artifact: ProgramArtifact,
) -> ProgramAnalysisResult
```

MVP 只接受 `architecture=arm`、`artifact_type=elf` 和存在的文件路径。装载
使用 `angr.Project(path, auto_load_libs=False)`，恢复使用
`project.analyses.CFGFast(normalize=True)`。非 ARM、raw binary、缺失文件和
无效 ELF 都由稳定的 ChipChain 分析异常拒绝。

所有 angr/CLE/CFG/Capstone 对象停留在 adapter 内。适配器不返回 CFG、
NetworkX 图或 AttackChain，也不直接操作 GraphRepository。

## Function Recovery

分析范围限定为 `loader.main_object`，并排除 SimProcedure 和 PLT Function。
每个恢复函数转换为 `BehaviorNode(kind=function, layer=firmware,
architecture=arm)`。

ID 使用 artifact ID 和规范化地址确定性生成，例如：

```text
synthetic-arm-call-chain:function:00010028
```

名称优先使用 main object 精确地址上的 function symbol；无符号时使用
`sub_<8位十六进制地址>`，不从名称猜测 driver、vulnerable 或 secure 等语义。
metadata 保存 function address/size、`recovered`、`symbol_backed`、backend 与
fixture provenance。

## CALLS 与 Evidence

已解析且 callee 属于 main object 函数集合的调用转换为 `CALLS` Edge。每条
Edge 引用一条 `static_analysis` Evidence，保存：

- artifact ID；
- caller/callee address；
- callsite instruction address；
- Capstone 能可靠给出时的规范化 instruction；
- direct/indirect、CFGFast 和 resolved provenance。

Edge 和 Evidence ID 都由 artifact、caller、callee 与 callsite 决定。输出 Node、
Edge 和 Evidence 在返回前按 ID 排序。

无法解析的 register-indirect call 只增加
`ProgramAnalysisResult.metadata.unresolved_calls`，不生成猜测 callee 或
CALLS Edge。已解析到 main object 之外的 direct call 单独计入
`excluded_external_call_count`。

## 自有 ARM Fixture 与 Ground Truth

fixture 位于 `tests/fixtures/angr/arm_call_chain/`，明确标记为 `synthetic`、
`owned` 和 `fixture`，不是漏洞样本。目录包含：

- `arm_call_chain.S`：人类可审计的 ARM A32 源码；
- `generate_fixture.py`：确定性 ELF32/A32 编码器；
- `build.ps1`：一键生成脚本；
- `arm_call_chain.elf`：生成的 32-bit little-endian ARM ELF；
- `ground_truth.json`：函数、直接调用、callsite 与未解析调用真值；
- `SHA256SUMS`：二进制 SHA-256。

当前机器没有 ARM GCC/Clang，因此没有下载未知预编译二进制；生成器直接写入
逐条注释的 A32 word 和最小 ELF header/program header/section/symbol table。
重新运行 build script 必须得到相同哈希。

Ground Truth 的解析链为：

```text
main@0x10028
  → parse_command@0x10018        callsite 0x10030
  → helper_function@0x10008      callsite 0x10020
  → driver_like_function@0x10000 callsite 0x10010
```

另有未被调用的 `indirect_dispatch@0x10038`，其 `blx r3@0x1003c` 目标故意
不受约束，用于证明 unresolved call 不会被伪造成 CALLS Edge。

## MMIO Phase 4B 状态

MMIO 未实现。单独看到 `STR`/`LDR` 不能证明 MMIO。后续只有在目标地址可靠
解析且命中显式配置的 known MMIO range 时，才允许生成 MMIO_WRITE/MMIO_READ
及地址解析证据；否则只记录诊断。

## 已知限制

- 只支持 ARM ELF，不猜测 raw binary 的 base、entry 或 ARM/Thumb 模式；
- CFGFast 是启发式恢复，可能漏报或误报；
- stripped binary 只能获得稳定合成名称，不能恢复语义名称；
- 间接调用只接受 angr 已可靠解析且命中 main object 函数的目标；
- 不分析共享库、extern、SimProcedure 或 loader stub；
- 尚未增加超时、函数预算、大型固件缓存或区域白名单；
- 本阶段未使用 Unicorn、QEMU 或动态执行；
- fixture 只验证提取管线，不代表真实固件覆盖率或漏洞检测能力。
