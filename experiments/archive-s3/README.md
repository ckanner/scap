# 独立 S3 兼容对象契约

本实验使用正式 `scap-archive::S3` 与独立 SeaweedFS 4.51 进程，验证签名 PUT/HEAD/GET、条件写入、对象大小约束、凭证拒绝、S3 进程 SIGKILL 和原目录重启。它不运行在单元 coverage profile 中，不实现或复制生产归档算法。

SeaweedFS 固定为官方 [4.51 release](https://github.com/seaweedfs/seaweedfs/releases/tag/4.51)，二进制版本包含源提交 `153ab668c99731a6d29492bf6c61d0b4fa701101`。官方 `linux_amd64.tar.gz` 的 SHA-256 为 `c03be37416a8ee672c77766e20b22a4e1430744c3af2668599a4b6eeaec14cee`，下载脚本先核验再解压。测试身份仅用于 loopback 本机临时进程，不能用于部署。

```bash
bash experiments/archive-s3/download-seaweedfs.sh /tmp/scap-seaweedfs
export SCAP_SEAWEEDFS_BIN=/tmp/scap-seaweedfs/weed
export SCAP_ARCHIVE_EVIDENCE_DIR=/tmp/scap-archive-evidence
cargo +1.90.0 fmt --manifest-path experiments/archive-s3/Cargo.toml --all -- --check
cargo +1.90.0 clippy --manifest-path experiments/archive-s3/Cargo.toml --all-targets --locked -- -D warnings
cargo +1.90.0 test --manifest-path experiments/archive-s3/Cargo.toml --locked -- --test-threads=1
```

两个测试都必须成功，并产生以 `verification passed` 结束的 `immutable-restart.log` 与 `orphan-outage.log`。测试结果与历史完整性是分别检查的条件。Rust/native 构建条件与正式 workspace 相同；需要 Linux amd64、可创建本机监听 socket、curl、tar、sha256sum 和临时磁盘。

默认使用固定二进制的 `mini` 子命令。执行环境若允许 loopback TCP、但不允许创建 Unix socket，可显式选择与 [真实服务契约](../service-network/README.md) 相同的上游四进程方式：

```bash
SCAP_SEAWEEDFS_MODE=separate cargo +1.90.0 test --manifest-path experiments/archive-s3/Cargo.toml --locked -- --test-threads=1
```

`separate` 通过正式 `master`、`volume`、`filer`、`s3` 子命令和显式 HTTP/gRPC TCP 地址启动同一版本后端。夹具用签名 HEAD/PUT 创建测试 bucket，随后仍以正式 `scap-archive::S3` 的签名条件 PUT 证明服务已就绪。停机步骤先确认四个进程仍在运行，再全部执行 SIGKILL 并核对退出信号；恢复步骤复用原目录、端口和测试身份。启动期间任何组件提前退出都会使测试失败，部分启动失败及测试退出也会清理已启动的进程。此选项不修改系统权限、上游源码或被测 S3 实现；历史记录包含实际版本、模式和进程数量。

首项直接证明 `If-None-Match:*` 不覆盖已有不同内容，过大的 HEAD 被拒绝，错误 secret 的签名不能读取对象，S3 进程重启后返回原始完整字节。第二项验证停机时原 deadline 已到的 PUT 不生成新对象，重启后既有不同 key 对象仍独立可读。是否发布及采用哪个归档由正式 cell 状态机和 Controller 决定，本 S3 端点实验不能单独证明归档发布或数据库唤醒正确性。

这是 S3 兼容协议与单机后端进程重启后的文件持久化实验，不证明 AWS S3、R2 或其他服务的持久性和一致性承诺，也不证明设备断电、生产 RTO、完整 DR 或可安全 GC。临时目录与后端日志保留用于检查，SeaweedFS 进程由 fixture 退出时清理。
