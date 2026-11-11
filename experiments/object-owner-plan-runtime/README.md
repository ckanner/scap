# 真实 owner-plan 故障合同

本目录实现 HEAD8 的独立实际验收。固定范围、身份、计数和期限见 [PLAN.md](PLAN.md)，确定性输入见 `spec.py`。**actual01 已执行并在 ACL 场景失败；本轮修订待提交冻结后执行 actual02。** [失败诊断](../../docs/evidence/owner-plan-actual01-acl-diagnosis-2026-11-11.json) 保留原源码、日志 SHA 和实际时间线，不回填通过。 只有正式冻结源码、构建 receipt 和全输入等价校验完成后才能执行。

## 验收范围

17 个完整 Scope、200 个 owner POST、46 份永久 Descriptor、45 次 admission、45 次终态以及 28 份永久 Proof。三个 owner ACK 丢失后只用保存的完整原输入恢复；Claim / Abort、Resume / Abort、同 actor 双 Resume、当前 ACL、替换 worker、迟到 legacy 操作、Proof 丢失或矛盾、预算错误不隔离、具名删除后的永久历史都经过真实公共接口。

原 SQL 共有 295 个成功 ACK：260 个由正式 native worker 建立三个 retained 窗口，其余 35 个由公开 SDK 提交。全部原结果字节和 receipt 留存。移除所有 9 份温缓存并退出全部温 worker 后，新 worker9203 冷恢复 16 个存活 Scope，逐字节 lookup 292 个成功结果，核对 1 个原取消、1 个被阻止的新请求 Unknown 和 16 份业务查询。具名旧 Scope 的另外 3 个 ACK 仍检查原件，但明确删除、seal 和 final-generation GC 后，其普通 lookup 必须返回 Lifecycle。

进程身份不复用。原进程退出后仍生效的 Descriptor / Claim / Active 请求分别保留原 invoke、owned wait4、真实后端 effect。旧目标在新 incarnation 上返回 TargetMismatch；新的 ADMIN 必须先结束旧 pending 计划，再创建目标明确的新原意图。这个合同不提供自动接管 controller，也不把数值 worker guard 当作网络身份认证。

## 观察与判定

公开 SDK 驱动在第一次 RPC 前持久保存 SQL、catalogue 和 owner 原输入，Prepared 只能来自真实 prepare 或 inspect。HTTP observer 区分产品实际响应与客户端收到的消息；S3 observer 分开保存后端原文与预先指定的故障投递。每个 observer 在 join 后记录独立请求总数，整条交换消失也必须被检出。

`audit_evidence.py` 验证原输入、两个构建身份、owned 退出、每条 HTTP/S3 原始字节及闭合分母。`audit_model.py` 独立解码 HEAD6/7/8、Descriptor、Proof 和完整不可变依赖。`oracle.py` 重新推导原 ETag、当前 ADMIN、全部 retained result 恢复、永久 Proof 的发布顺序、进程退出后的 effect、原 UNKNOWN 和原 SQL receipt；不以 runner 的 PASS 标签作证据。runner 只返回 `OBSERVED_NOT_AUDITED`。

`controls.py` 创建 42 份完整反例和 1 份原样正控。副本初始复用只读 hardlink，任何修改都先断开链接；所有副本和每个目标 guard 的结果都保存。负控必须命中指定语义拒绝，其他异常或不相关格式错误都算失败。源 raw evidence 的全文件 inventory 最后重新校验。程序不会删除失败副本。

70 个轻量单位包含真实公开 SDK save/restore、并发两个 Resume/Abort 的 Fetch 归属、25 个 HTTP observer loopback 边界、实际签名 S3 loopback 的两次相同 hash 变异与连续两次 NoSuchKey、独立 decoder 和原件保护。这些 loopback 响应是明确的夹具单位，不是原生产品验收。

## 正式命令

从已提交且干净、包含本目录的 checkout 执行。原 service/native release receipt 可以来自更早的产品提交；两者必须指向同一个 runtime commit，所有 receipt 记录的生产、SDK、native assembler 输入必须在当前 fixture checkout 中逐字节相同。runner 和 oracle 都检查这种等价关系，不重命名二进制的真实源提交。

以下路径为示例。所有 evidence、controls、manifest、stdout/stderr 和命令账本路径都应为新路径。正式候选 HEAD8 的 native receipt 是完整的 `native-build-head8-02/build.json`，不能使用没有结束记录的第一次 native 构建目录。

```bash
python3 -B -m unittest discover -s experiments/object-owner-plan-runtime -p 'test_*.py'
node --check experiments/object-owner-plan-runtime/client.mjs

python3 -B scripts/source_manifest.py capture \
  /absolute/evidence/owner-fixture-source.json

python3 -B experiments/object-owner-plan-runtime/run.py \
  --server /absolute/target/service/release/scapd \
  --build-record /absolute/evidence/service-build/build.json \
  --worker /absolute/target/native/release/scap-object-network \
  --seed-build-record /absolute/evidence/native-build-02/build.json \
  --weed /absolute/bin/weed \
  --node /absolute/bin/node \
  --evidence /absolute/evidence/owner-head8-01

python3 -B experiments/object-owner-plan-runtime/oracle.py \
  /absolute/evidence/owner-head8-01 > /absolute/evidence/owner-head8-01-oracle.json

python3 -B experiments/object-owner-plan-runtime/controls.py \
  /absolute/evidence/owner-head8-01 \
  --output /absolute/evidence/owner-head8-01-controls

python3 -B scripts/source_manifest.py verify \
  /absolute/evidence/owner-fixture-source.json
```

需要按顺序保存每条命令的原 stdout、stderr、退出状态和时间，任一失败都停止认定合同通过。正式 actual 只接受原来固定的 180s hold、1200s 整体上界、服务/SDK 原期限和固定工作量。失败后保留旧目录，通过新提交、新 checkout、新 attempt 修复，不修改旧结果或补造前置。完成本合同也不产生 AWS Standard、跨地域、通用吞吐 SLO 或永久空前缀结论。
