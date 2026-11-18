# 真实大响应截止、提交知识和关闭验收

[PLAN.md](PLAN.md) 是执行前固定合同。此夹具补充父目录的 `/healthz` TCP 合同，使用
真实 daemon、原生 SQLite、已签名 SeaweedFS S3 和正式 Node SDK。它不替代独立 Rust 单元
四维覆盖，也不证明 AWS Standard 云端合同或生产吞吐 SLO。

四个慢 TCP 响应分别验证停止读、分段读一个字节、已提交写响应截断，以及 SIGINT 关闭。
每个响应大于 21 MiB；客户端只读响应头并保留真实 socket。前三个必须在固定 2 秒发送期限
后观察服务端截断，最后一个必须在固定 500 ms 连接关闭窗口后回收 owned daemon。
真实时序容差见 PLAN；确定性时钟精确边界、stream producer gaps、Hyper 最后一帧和 backing
析构顺序由 `crates/scap-service/src/transport/tests.rs` 单元测试覆盖。

`INSERT ... RETURNING` 只发送一次，截断后用保存的原请求身份 `lookup`，验证原始结果
hash、receipt、实际 S3 HEAD CAS、结果对象回读、`COUNT(*) = 1`。关闭连接不取消事务，
不把半个 HTTP 响应转换为 committed/rolled-back；客户端仍须按 UNKNOWN 处理并 lookup。

## 执行

先按 `experiments/object-service/build.py` 生成冻结源码的 release build receipt。
需 Node 22.16.0 和仓库固定 SeaweedFS 二进制；evidence 目录必须尚不存在。

```bash
python3 experiments/bounded-transport/response/run.py \
  --source-root "$PWD" \
  --server /tmp/scap-service-target/release/scapd \
  --build-record /tmp/scap-service-build/build.json \
  --weed /path/to/weed --evidence /tmp/scap-response-evidence
python3 experiments/bounded-transport/response/oracle.py /tmp/scap-response-evidence
python3 experiments/bounded-transport/response/controls.py /tmp/scap-response-evidence
python3 -m unittest discover -s experiments/bounded-transport/response -p 'test_*.py' -v
```

raw TCP observer、事件记录和配置骨架复用 `experiments/output-pool` 的已验证 helper。
归档包含这些共享 fixture 源码；独立 oracle 只复用 raw-file/identity/protocol 解析器，
不导入 runner 或产品实现。fixture 自测的合成观察不是实际 TCP 证据；原 10 个负控从真实目录
的副本修改原始观察后重新审计，原始目录在前后均须通过。

启动阶段复用 output-pool 的独立永久身份审计：以配置中的 5001、冻结二进制、原 owned
process、`Popen` 前时钟与 ready 证明唯一 marker 的条件 PUT 和完整 GET。32 字节 wire hash、
两次原 ETag、backend/delivery 都必须一致；不会把 startup S3 混入 11 个业务 HTTP 的分母，
也不跳过未知 prefix。六个新增完整记录负控逐项破坏回读、wire body、ETag、Absent 条件、
实例号和 ready 区间，总计 16 项；共享负控源码也进入 fixture archive。实际验收仍使用
原 2 秒响应期限、500 ms 关闭期限和全部既有时序容差。

`--transport-profile baseline` 仅用于旧二进制反例，省略旧版不认识的新字段。旧服务会在
等待后继续发送完整响应，runner/oracle 应拒绝并保留失败原始证据。不要将 baseline
反例失败误记为候选失败，也不要用改短候选窗口掩盖候选观察的失败。

正常结束只记录服务端 EOF/reset；只有失败清理可请求客户端主动 RST，并留下单独事件。
每个子进程身份、owned wait4、服务二进制/native archive/build receipt、fixture hash 和
单调时序均保留。全部实际运行均禁止 LLVM_PROFILE_FILE 和插桩产物。
