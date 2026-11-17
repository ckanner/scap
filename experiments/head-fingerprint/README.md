# HEAD 指纹的有界微型性能分析

此实验比较相同 `Head` 的三种内存表示：原先的 JSON 缓冲区加十六进制
SHA-256、产品的 JSON 缓冲区加二进制 SHA-256，以及直接流入 SHA-256 的
候选实现。调用真实私有产品函数；不把独立重写的函数当作产品测速。

普通单元测试只运行 `head_fingerprint_tests.rs` 中的完整正文等价检查。
计时夹具保存在本目录，必须注入一份临时 checkout，不能提交到生产模块或
作为被忽略的必需单元测试。`profile.rs` 借用产品测试中的固定合法 HEAD，
分别使用小型记录与达到 `MAX_PRINCIPALS` 的记录。它不模拟数据库执行。

## 复现

使用仓库固定的 Rust 1.90.0、`Cargo.lock` 与 native 依赖。先停止本机其他构建和
负载；每次 profile 使用新的临时目录和专属 Cargo target，保留 stdout、构建日志和
最终可执行文件的 SHA-256。不同 checkout、候选或负控不能共享 target，即使按顺序
构建也不复用；已观察到跨 worktree 产物混用，不能仅凭源文件未变排除旧产物。

1. 将当前 checkout 复制到临时目录，排除 `.git`、`target`、运行日志与缓存。
2. 将本目录的 `profile.rs` 复制为临时目录中的
   `crates/scap-object/src/head_fingerprint_profile.rs`。
3. 仅在临时 `crates/scap-object/src/object_context.rs` 末尾追加：

   ```rust
   #[cfg(test)]
   #[path = "head_fingerprint_profile.rs"]
   mod fingerprint_profile;
   ```

4. 在临时目录构建并运行唯一计时入口：

   ```bash
   export CARGO_TARGET_DIR="$(mktemp -d /tmp/scap-fingerprint-target.XXXXXXXX)"
   cargo test --locked --release -p scap-object --lib \
     object_context::fingerprint_profile::profile -- \
     --exact --nocapture --test-threads=1
   ```

输出两条 `FINGERPRINT_PROFILE` JSON。每种输入运行九轮；每轮轮换三个候选的
执行顺序。小 HEAD 每个样本 20,000 次，大 HEAD 每个样本 1,000 次。保留所有
样本及实际 JSON 字节数，不删除较慢样本。比较中位数只用于描述这次有界实验，
没有事后设置通过阈值。

## 结论边界

- 单位是每次指纹计算的墙钟纳秒；不是 HTTP TPS、数据库提交延迟或纯 CPU 时间。
- 没有 allocator、锁等待或对象传输的采样；删除分配的结论来自代码，不能将其
  写成已经测量到的 RSS、每事务分配总量或端到端收益。
- 所有候选必须保持完整 HEAD 正文绑定。不能删掉权限、owner、保留结果、快照、
  Scope、ETag、lineage 或原 deadline 的检查以取得更快结果。
- 这项实验不能解释先前四库写入约 24% 的回退。实际服务 CPU／等待分析、S3
  合同、持续负载与真实云端验证仍须分别完成。
