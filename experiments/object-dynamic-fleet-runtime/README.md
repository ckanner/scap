# 受信动态 owner fleet 实际验收

固定合同见 [PLAN.md](PLAN.md)，产品语义见
[动态 fleet 设计](../../docs/architecture/dynamic-owner-fleet.md)。本工具装配正式服务、SDK
和 CLI，复用原始 HTTP/S3/进程观察器；不包含业务 owner 或路由实现。

先提交冻结源码，再创建全新的正式 release 构建与证据目录：

```sh
python experiments/object-service/build.py --target-dir /path/to/new-target --evidence /path/to/new-build
python experiments/object-dynamic-fleet-runtime/run.py \
  --server /path/to/new-target/release/scapd --build-record /path/to/new-build/build.json \
  --weed /path/to/weed --node /path/to/node-22.16.0 --evidence /path/to/new-actual
python experiments/object-dynamic-fleet-runtime/oracle.py /path/to/new-actual
python experiments/object-dynamic-fleet-runtime/controls.py /path/to/new-actual
```

`OBSERVED_NOT_AUDITED` 只表示原实际流程结束；必须继续通过独立 oracle 和全部反例。
后者读取真实原始输入和结果，检查历史、guard、原 recipe、未知响应、源码和owned清理，
不读取controller源码来决定通过。反例修改内存中的观察副本，不修改实际原件或把反例
当作新故障执行。完整本地结果也不替代AWS Standard、生产SLO或分布式registry验收。
