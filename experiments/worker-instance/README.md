# 实际进程的永久 worker identity 启动合同

`run.py` 只装配正式 `scapd`、已固定的 SeaweedFS 4.51 和实际签名 HTTP。
产品代码负责条件创建与 exact GET；夹具不实现或替换身份分配、启动或 fencing。
它不设置 `LLVM_PROFILE_FILE`，不能用这份进程验收补单位覆盖。

固定场景：首次启动、存活进程的重复 ID、正常退出后的重复 ID、全新 ID、SIGKILL 后
重复 ID、两个实际进程同 ID 竞争、后端接受 PUT 后丢失 ACK、UNKNOWN 的 ID 仍被占用、
创建后回读被篡改，以及不可达后端。失败必须退出码 1、稳定错误码、未开放 listener、
未创建执行 cache；相同 ID 冲突不得继续 GET 或重试 PUT。

回读篡改通过夹具管理员对真实后端做一次故障写入，故意违反部署的不可变政策，
仅用于验证拒绝损坏。它不表示产品具备修改或删除 marker 的能力。

```bash
python3 experiments/worker-instance/run.py \
  --binary /path/to/frozen/scapd \
  --weed /path/to/pinned/weed \
  --evidence /tmp/scap-instance-new-run
```

runner 保存源码文件摘要、实际 executable/backend 摘要、每次原始请求/响应摘要和
条件头、每个 owned Popen 子进程的身份/退出状态、原始 stderr 及最终结果。
证据目录必须新建，失败也保留。源码与 binary 的构建对应仍须配套冻结构建日志。

本地兼容端点不证明 AWS Standard 条件写、目标 IAM policy、跨区域恢复、混合旧版
部署或历史身份迁移已经通过。身份 marker 必须从首次启用起永久保存，完整边界见
[设计](../../docs/architecture/worker-instance-claim.md)。
