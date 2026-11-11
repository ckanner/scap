# Owner Descriptor absence：真实并发回归

这是 `owner_prepare` 对合法 Missing 交错的独立实际验收。范围、输入、期限和 13 个反例固定在 [PLAN.md](PLAN.md)。actual01 的原始观察已完成，但原 oracle 误把公开 query 的 `{statements}` 当成 committed wrapper，正式审计失败。本修订独立解码并逐字段校验 query，待冻结后以新 actual02 重跑全部门禁；[失败与诊断记录](../../docs/evidence/owner-absence-actual01-query-oracle-diagnosis-2026-11-11.json) 保留原日志，未冻结诊断、单位/loopback 不代表正式通过。

三个 Scope 分别验证：原404之后另一 daemon prepare+Claim；原404之后另一 daemon 将计划替换成永久历史；两次真实404与稳定 HEAD 之后出现新 Proof，此时必须再读变化的 HEAD 并 Conflict。所有正例 hold 都位于实际 S3 后端响应之后，不改 HEAD/ETag、不注入 Missing、不删除对象。

正式 `scapd` 内 native SQLite 创建并提交 6 份带随机值的 SQL 原结果，OwnerPlanClient 通过公开 HTTP API 完成 27 次 owner POST。竞争结束后逐字节 lookup 6 份原结果，3 次业务查询验证原行。服务、SDK、后端进程都有 owned wait4，所有 HTTP/S3 原始字节和关闭分母保存；oracle 复用独立格式解码器和 closure verifier，但不导入 runner/输入生成器/产品实现。

## 固定命令

从已提交且干净的 checkout 执行。e3 的 service/native build receipt 可复用，前提是两个 receipt 的 runtime commit 相同，所有生产、SDK、native assembler 输入与当前 fixture checkout 逐字节相同。native seed receipt 用于同源验证；本合同不启动 seed worker。

```bash
python3 -B -m unittest discover -s experiments/object-owner-plan-runtime -p 'test_*.py'
python3 -B -m unittest discover -s experiments/object-owner-absence-runtime -p 'test_*.py'
node --check experiments/object-owner-plan-runtime/client.mjs

python3 -B scripts/source_manifest.py capture /absolute/evidence/absence-source.json

python3 -B experiments/object-owner-absence-runtime/run.py \
  --server /absolute/target/service/release/scapd \
  --build-record /absolute/evidence/service-build/build.json \
  --worker /absolute/target/native/release/scap-object-network \
  --seed-build-record /absolute/evidence/native-build/build.json \
  --weed /absolute/bin/weed --node /absolute/bin/node \
  --evidence /absolute/evidence/owner-absence-01

python3 -B experiments/object-owner-absence-runtime/oracle.py \
  /absolute/evidence/owner-absence-01 > /absolute/evidence/owner-absence-01-oracle.json
python3 -B experiments/object-owner-absence-runtime/controls.py \
  /absolute/evidence/owner-absence-01 --output /absolute/evidence/owner-absence-01-controls
python3 -B scripts/source_manifest.py verify /absolute/evidence/absence-source.json
```

各命令的源码身份、起止、退出码、stdout/stderr 各自保存到新目录。反例控制不会修改原件。该合同补充主 owner-plan 的并发安全边界，不替代主合同的原生独立 worker、retained 三窗口、进程退出和全部本地缓存丢失验收。
