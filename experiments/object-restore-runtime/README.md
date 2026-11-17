# S2 实际恢复专项

`run.py` 复用既有 pinned SeaweedFS 4.51 进程夹具；`probe.mjs` 使用正式 Node SDK、
实际 `scapd` HTTP、native SQLite 和签名 S3。产品逻辑只在 Rust crates 中。

```bash
python experiments/object-restore-runtime/run.py \
  --server /absolute/path/to/scapd \
  --weed /absolute/path/to/weed \
  --node /absolute/path/to/node \
  --evidence /absolute/path/to/new-empty-evidence-directory
```

六项合同覆盖原随机值/多块 BLOB、Empty/Restore first-winner 槽、复制被挂起时的取消、
源权限撤销、HTTP 成功响应丢失后 SIGKILL/新 ID/空缓存继续，以及源 payload 实际 DELETE
并逐个 GET=404 后目标全冷恢复。冻结输入、保存原 restore 意图，每次推进一个明确
resume；实验中的有限阶段循环不是客户端的自动重试策略。

透明代理只暂停已经签名的 payload GET，不修改正文、ETag、条件头或返回状态。原始
请求历史、进程错误与每项结果写入独立 evidence 目录。后端凭据只在临时私有配置与
子进程环境中，禁止提交配置、日志、数据库和 credential。

这是固定小库的实际故障专项，不替代 Rust/Node 单元覆盖、完整容量、长期过载、AWS
Standard/IAM、S3 Express 故障域或生产 SLO。原始失败与新的完整通过必须分别保留。
