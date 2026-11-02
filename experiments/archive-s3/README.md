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

首项直接证明 `If-None-Match:*` 不覆盖已有不同内容，过大的 HEAD 被拒绝，错误 secret 的签名不能读取对象，S3 进程重启后返回原始完整字节。第二项验证停机时原 deadline 已到的 PUT 不生成新对象，重启后既有不同 key 对象仍独立可读。是否发布及采用哪个归档由正式 cell 状态机和 Controller 决定，本 S3 端点实验不能单独证明归档发布或数据库唤醒正确性。

这是 S3 兼容协议与单进程文件持久化实验，不证明 AWS S3、R2 或其他服务的持久性和一致性承诺，也不证明设备断电、生产 RTO、完整 DR 或可安全 GC。临时目录与后端日志保留用于检查，SeaweedFS 进程由 fixture 退出时清理。
