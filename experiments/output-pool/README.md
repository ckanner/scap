# 真实输出池压力验收

本合同验证普通 `/v1` 编码 backing 在真实慢 TCP 消费者下的租户/全局额度、
控制分区、断开释放，以及已提交但结果暂不可输出的原请求查证。固定输入与明确边界见
[PLAN](PLAN.md)。不访问私有 pool，不修改正式 daemon，不以 mock 代替 native SQLite/S3。

```bash
python3 -m unittest discover -s experiments/output-pool -p 'test_*.py' -v
python3 experiments/output-pool/run.py \
  --source-root /absolute/frozen-source \
  --server /absolute/release/scapd \
  --build-record /absolute/service-build/build.json \
  --weed /absolute/weed \
  --transport-profile bounded \
  --evidence /absolute/new-output-evidence
python3 experiments/output-pool/oracle.py /absolute/new-output-evidence
python3 experiments/output-pool/controls.py /absolute/new-output-evidence
```

`--source-root` 必须与正式 `object-service/build.py` 收据匹配。运行时/build/SDK/helpers
与本新夹具分别记录并归档；可以验证已有 frozen release，但不改收据、不冒充在新源码上重编。
`baseline` profile 只适用于尚没有两个 transport 期限字段的历史二进制，不能证明响应期限。
每次证据目录必须全新，原失败不会被覆盖。root 完成实际运行、独立审计和负控前，状态为 `NOT_RUN`。

`run.py` 成功只写 `OBSERVED_NOT_AUDITED`；必须独立运行 oracle/controls。
18 次 POST 的完整请求均保存；A1 的 header-only 响应被主动 reset，不伪称完整 ACK。
另外 17 次响应保存完整原文；三条排空的慢响应及后续查询逐字节检查 32 MiB BLOB。
唯一 INSERT 在压力下持久提交，先返回 `COMMITTED_BUT_UNAVAILABLE`，解除压力后
用同一身份 `lookup` 返回原 receipt/result，COUNT=1。原九个实际历史负控保持原拒绝规则。

单次 daemon 启动使用 5001，fresh backend 不复用历史 worker。新增独立 startup 审计
将配置、冻结二进制、原 owned process、`Popen` 前时钟和 ready 绑定；精确验证两次
永久 marker PUT/GET 的条件创建、32 字节 wire hash、原 ETag、完整 backend/delivery
和 ready 前完成。只有这两次已证明的交换从业务请求计数分离，全部 S3 交换仍审计，
18 次 HTTP 分母与输出压力、期限保持不变。`worker_startup` 单列这两次访问。

另外六个完整原始记录负控覆盖缺失回读、错误 wire body、不同 ETag、replacement PUT、
错误实例和 ready 后回读，总计 15 项。变更同步覆盖完整 exchange 的各事件；删除 exchange
后修复 serial 分母，使失败必须来自目标身份规则。新夹具需重新冻结并使用相符的正式
build receipt 完成 actual；合成 helper 单元不替代这项验收。

`io.SlowResponse` 可供独立短响应期限测试复用。它在 connect 前设置小 TCP 接收窗口，
构造时只逐字节读 header，`drain(allow_truncated=True)` 区分 peer EOF/reset 与主动
`disconnect()`；不自动把 socket 超时或截断变成成功。它不实施数据库协议。

私有凭据、后端目录和计算缓存只在成功清理后删除，不作为公开 artifact；失败保留路径。
所有 daemon/Node/后端由 owned child 的 wait4 记录结束，HTTP proxy 停止并 join。
该合同不证明 AWS Standard、生产吞吐/延迟 SLO、整进程 RSS、公平调度或其他路由的输出预算。
