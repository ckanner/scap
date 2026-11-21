# 独立事务 group commit 的实际合同

本目录只装配正式 `scapd`、未修改的 Node SDK 和经认证的固定 SeaweedFS 4.51 后端。
产品实现位于 crates，协议见[设计](../../docs/architecture/independent-group-commit.md)。
本地兼容 S3 不代表 AWS Standard/Express 或生产 SLO 认证。

## 冻结工作

`spec.py` 固定全部 SQL、原身份、Scope、两个永久 worker ID 和资源配置。组上限为 4，
普通库队列上限为 4；先在真实 HEAD GET 停住一个原操作，加入 4 个独立请求，用额外
BACKPRESSURE 响应证明队列已满，再释放 actor。不以 sleep、完成时间或客户端批次名
证明实际组批；观察器必须从最终 HEAD 和全部新增 StoredResult 证明 +k。

七个组阶段：

| 阶段 | 固定验证 |
| --- | --- |
| success | 真实独立 DDL、前序可见性、重复页更新、只读/no-op 成员，4 个原结果一次发布 |
| first_failure | 首成员 deferred FK 在自己的 COMMIT 失败；后续补父行不能挽救它，3 个未开始成员随后继续 |
| middle_failure | 成功前缀 1、失败成员 1、未开始后缀 2，后缀只运行一次 |
| last_failure | 成功前缀 3 可发布，末成员失败不泄漏数据 |
| duplicate | 已提交的原身份触发 SQL 前回退，返回原随机结果；后续全新请求继续组批 |
| cancel_race | 在原组 HEAD PUT 前停住，控制池对中间成员先安装取消屏障；原候选 412，四成员不换 ETag、不重放 |
| response_loss | 一次组发布后只丢其中一个 HTTP 成功响应，其身份 UNKNOWN；其他成员结果保持独立 |

随后 SIGKILL 第一服务，按原字节摘要记录并删除全部本地缓存，使用全新永久实例身份、
空目录和原 S3 启动第二服务。显式 takeover/activate 后，用保存的原请求逐个 lookup，
包括从未收到 ACK 的那个成员；核对原 receipt、非确定性结果、最终业务行、失败事务
无泄漏，并从对象闭包重建原始 SQLite 文件，独立执行 `PRAGMA integrity_check`。

## 运行

工具固定 Rust 1.90.0、Node 22.16.0、SeaweedFS 4.51。Seaweed archive SHA-256 与
`.github/workflows/next-runtime.yml` 一致。先冻结并提交源码；build/run 期间不能编辑
已登记输入，新增文件必须进入 Git 源码清单。

```bash
python3 -B -m unittest discover -s experiments/group-commit -p 'test_*.py' -v
python3 -B experiments/group-commit/model.py
python3 -B experiments/object-service/build.py \
  --target-dir /tmp/scap-group-release --evidence /tmp/scap-group-build
python3 -B experiments/group-commit/run.py \
  --binary /tmp/scap-group-release/release/scapd \
  --build-record /tmp/scap-group-build/build.json \
  --weed /path/to/weed --node /path/to/node \
  --evidence /tmp/scap-group-actual
python3 -B experiments/group-commit/oracle.py /tmp/scap-group-actual
python3 -B experiments/group-commit/controls.py /tmp/scap-group-actual
```

`run.py` 拒绝 unit instrumentation，保存完整 source archive、build receipt、native
archive 身份、工具摘要、实际配置、真实 HTTP/S3 原字节、客户端原输入/结果和进程
内核退出证据。凭据、数据库、日志和生成原件不提交 Git；失败原件保留，后一次实际
使用新目录。oracle 先核对来源，再核对原字节和版本链，不导入生产实现。

## 证明范围

`model.py` 的 2,940 个有限调度区分独立成员、控制竞争、依赖失败、丢回复和本地收养
失败；`test_model.py` 加入定向错误轨迹。它们不模拟完整 SQLite 或 S3。
`test_protocol.py` 和 `controls.py` 检查观察器能拒绝伪证；投影反例明确标注，不计作
新进程运行或新数据库故障。每个真实阶段严格要求原 HTTP 次数、原 SQL、原指纹和
实际服务回复；少一次请求、换一条失败 SQL 或共享一个 revision 都不能通过。

旧单事务实验保持默认关闭组提交，仍严格检查每次物理 HEAD 更新 +1；本目录的 +k
例外只允许恰好 k 个新增完整 committed records，并复核每成员顺序、原结果、最终根、
未变保护字段、依赖回读、原 ETag 和所有成员请求区间。结果报告同时列出独立请求数
和实际 accepted HEAD 数，不以语句数或数据行数替代事务数。

当前固定合同主要证明正确性、请求合并和恢复。固定开环配对性能、云端条件写、长期
GC/成本和跨故障域恢复仍须独立验收；这里不输出产品 TPS 或生产尾延迟结论。
