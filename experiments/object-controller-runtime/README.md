# 生产 controller CLI 的本地组合回归

该夹具执行 [固定合同](PLAN.md)：生产 CLI 自动接管、真实 HTTP/Node/native SQLite/
逐请求 SigV4 本地 S3、丢失业务 ACK、丢失 claim ACK、controller 重启、owner 缓存
删除、原始结果恢复、旧 worker guard 与 HEAD9 snapshot 字段保留。

它复用原 owner HTTP 代理及签名 S3 代理，不实现第二套 controller 或数据库算法。
`run.py` 只报告 `OBSERVED_NOT_AUDITED`；`oracle.py` 从完整原始记录独立判断，
`controls.py` 对内存副本的九种特定破坏逐项检查，原件不改动。

## 运行

需要干净、已提交源码，固定 Node 22.16.0 / SeaweedFS 4.51，以及由
`experiments/object-service/build.py` 产生的 release `scapd` 和原 build receipt。
该 receipt 包含实际静态链接的原生 SQLite archive；不需要另一个模拟 worker。
证据目录必须不存在且在源码目录外；每次失败和重验使用不同目录。

```bash
python -m unittest discover -s experiments/object-controller-runtime -p 'test_*.py'
python experiments/object-controller-runtime/run.py \
  --server /absolute/path/to/service-release/release/scapd \
  --build-record /absolute/path/to/service-build/build.json \
  --weed /absolute/path/to/weed \
  --node /absolute/path/to/node \
  --evidence /absolute/path/to/new-controller-actual
python experiments/object-controller-runtime/oracle.py /absolute/path/to/new-controller-actual
python experiments/object-controller-runtime/controls.py /absolute/path/to/new-controller-actual
```

180 秒是此单一小库回归的总运行观察界限。生产 controller 的固定 5 秒 tick、失败
窗口、每轮至多一个变更和真实 HTTP 生命周期保持原样。不要把该本地结果转述成生产
failover SLO、AWS AZ 验证、完整 controller 并发矩阵或完整 snapshot/restore 验收。
这三个命令的实际结果及对应源码 SHA 应分别记录；新增夹具本身没有通过含义。
