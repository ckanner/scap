# GC 存储接口的真实后端合同

状态：夹具开发中，真实运行及正式覆盖率 NOT_RUN。该 worker 只装配
`scap-object-store::GcS3`，不实现 HEAD/退休/pin/删除算法，不运行 SQLite。
产品物理 GC 仍关闭。

冻结计划 `plan.py` 包含 42 个调用场景、预期 115 次生产存储请求。四个 worker
使用同一个固定 release executable，后端为固定 SeaweedFS 4.51。独立 auditor
重读全部 stdin/stdout、原始 HTTP、前后对象 bytes/ETag 和 8 个子进程的 owned
wait4 记录，并用夹具私有凭据重新计算签名；审计报告不包含这些凭据。
这只是本地兼容性合同，不是吞吐测试，也不证明 AWS 条件删除实现。

候选提交并保持 clean 后运行：

```sh
python3 experiments/object-gc-store/build.py --target /tmp/scap-gc-release-UNIQUE --evidence /tmp/scap-gc-build-UNIQUE
python3 experiments/object-gc-store/run.py --worker /tmp/scap-gc-release-UNIQUE/release/scap-object-gc-store --build-receipt /tmp/scap-gc-build-UNIQUE/build.json --weed /path/to/pinned/weed --evidence /tmp/scap-gc-run-UNIQUE
```

原始 `run.json` 只有在全量审计及十三项负控、一项正控通过后才写 `passed`。
Python 夹具的九项单测仅检查审计基础行为、构造日志失败时仍回收 owned child，
以及真实 HEAD/POST/未知方法均被代理记录并拒绝，不能替代真实后端与 Rust unit-only
四维覆盖。任何失败都保留原目录，用新目录重跑；不修改已经冻结的候选。

首次 `7a8b443` 的真实运行完成全部 42 场景，旧 oracle 报告通过。但独立复查
构造出了重复 worker/backend 身份、配置晚于实际交付以及结果早于交付的审计
假阳性；旧记录不构成本合同的完整接受。新观察分别记录首次 backend send 前
的 `forward_started_ns` 与响应 `delivery_attempt_ns`，验证原 deadline 后才转发、
配置变化在真实交付前、每个同时存活的子进程唯一且被 owned wait4 回收。
这些修正是新候选，不能给旧 history 补造缺失事件或把旧报告改写成新通过。

配置文件只放实验独有 endpoint、bucket、临时凭据和 deployment。stdin 每行
一个有界命令，指定固定 prefix、原 deadline 和候选 hash/ETag。空候选列表只
执行真实后端配置检查；最多允许 33 个候选，用最后一个验证生产 32 次上界。
命令原件、完整 stdout/stderr、backend/代理请求、身份与进程退出记录须单独保存。

冻结合同必须包含：错误 ETag 不删除且原 body/ETag 不变；正确 ETag 删除并独立
GET 缺失；重复请求不虚构释放字节；Enabled/Suspended/ObjectLock/未知配置拒绝；
畸形、超限、redirect、401/403/404/409/500 和完整 deadline；跨 deployment、
HEAD/Catalogue/非法hash零 DELETE；32 次额度；后端已执行 DELETE 后响应丢失与
原请求超时后迟到 DELETE。

还需实际把 bucket 配置改变放在已完成配置 GET 与 DELETE 之间，保留该竞态的
完整原始证据，确认异常版本/delete-marker 响应是 UNKNOWN 且当前 batch 关闭。
此例不能替代部署期固定配置前提，或被写成版本化回收已受支持。

独立 oracle 依据冻结命令、真实 wire、原 ETag、后端前后原 bytes、完整进程账本
判定；负控须删除一个原调用、改写 ETag/签名/结果、把已落地未知删除改成确定
未执行，并使对应判定失败。用同一调用返回的摘要当作唯一 oracle 不足以通过。
真实 AWS、完整数据库 pin/drain、持久计划、迟到对象重建后的多轮清扫和 PITR
仍是另外的产品验收，不能从这个传输合同推导。
