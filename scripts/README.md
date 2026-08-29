# Scripts

后续阶段在此保存可复现的数据准备、验证和评测脚本。核心业务逻辑应位于 `src/chipchain`，而不是脚本中。

`run_public_knowledge_experiment.py` 为 Phase 10D Step 8B-1C 的窄入口：

- `--preflight-only` 只读取冻结 public cohort/readiness/corpus，构造正常 Phase 10D plan/input 与独立
  public execution binding，并离线重建、审计全部 40 个 projected prompt；不会读取 Provider 环境变量、
  实例化 Provider 或访问网络。
- `--execute-real-provider` 是后续 Step 8B-1D 才可人工选择的一次性显式 opt-in，且要求 `--output`；
  import、`--help` 与 `--preflight-only` 都不会触发 Provider。

示例离线检查：

```bash
python scripts/run_public_knowledge_experiment.py --preflight-only
```

脚本不包含 retry、Mock fallback、prompt tuning 或 QEMU 路径。输出 wrapper 只保存 typed public input、
prompt/response hashes、bounded execution accounting 与 parsed reasoning semantics，不保存 assembled prompt、
raw provider response、secret、endpoint 或 proxy。
