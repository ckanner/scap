# 真实 HTTP 服务与 Node SDK 合同

这个实验启动正式 `scapd` 和正式无依赖 Node SDK，通过真实 HTTP/SigV4/S3 调用固定 SeaweedFS 4.51。实验不实现数据库协议，不贡献 Rust 或 SDK 单元覆盖率，也不会发现、创建或修改 AWS 资源。

## 运行

在固定 Rust 1.90、Node 22.16.0 与原生编译依赖就绪后：

```bash
python3 experiments/object-service/build.py \
  --target-dir /absolute/isolated-release \
  --evidence /absolute/new-service-build
python3 experiments/object-service/run.py \
  --server /absolute/isolated-release/release/scapd \
  --weed /absolute/weed \
  --build-record /absolute/new-service-build/build.json \
  --evidence /absolute/new-service-evidence
```

build receipt 绑定实际 stable release、所有 Rust/SDK/fixture 输入和工具版本，并记录构建时实际 native libSQL archive 的摘要。最终运行在开始与结束核对源码输入清单、`scapd` 字节以及实际 Node／S3 可执行文件摘要；运行时不重新链接或读取 archive。`--diagnostic` 只用于开发定位，不产生冻结验收结论。缺二进制、缺收据、测试失败或清理错误都非零退出。

## 实际判据

1. 无效 bearer 和跨租户 scope 拒绝；拥有正确服务身份仍须获得当前 HEAD 权限。
2. SQL i64、随机 BLOB、Unicode/BOM/NUL、随机 RETURNING 原结果无损。重复请求、lookup 与 committed cancel 返回同一完整 receipt 和原字节；改 SQL 却复用 ID 拒绝。
3. Cancelled 身份不能再提交；撤权使暖会话的新读立即拒绝。一个库维护不改变另一租户库的数据。
4. 两个独立 daemon 并发创建同一 ID，恰好一个成功、一个 Conflict；双方观察同一 HEAD 身份。
5. 在真实后端已接受 HEAD 后丢失响应，execute 保持 UNKNOWN；使用原身份 lookup 找回随机原结果，不重放 SQL。
6. 已有热缓存时阻断远端 HEAD GET，query 必须失败。
7. 第二 daemon 显式 takeover/activate 后，旧 daemon 写入必须 FENCED。
8. SIGKILL 全部 daemon，删除全部本地计算缓存，SIGKILL 四个对象后端进程，再从原对象目录和全新 owner 恢复。两个租户的有数据数据库分别接管、激活并实际读表，核对 9+1 条业务记录；独立核对全部 ACK、业务 BLOB 哈希、取消屏障与未收到 ACK 的原结果。

测试包含 10 个唯一成功请求、8 次成功重复 execute，共 18 次成功 execute 响应，另有 1 次 execute UNKNOWN。重复响应独立记账并在恢复后全部重查；UNKNOWN 的后续 committed 查证单独记账，不修改原尝试分母。随机业务输入在发送前写入独立 fsync 账本，ACK 只在客户端真实观察 committed 后登记。恢复比较完整字节，不只比较行数。未知写的实际 SDK Fetch 调用次数必须为 1，不能用常量声明没有重试。

公开 evidence 包含源码/构建身份、网络历史、输入、ACK、UNKNOWN 查证、阶段结果和清理状态。private fixture 目录另存随机测试凭据、日志和数据库；它从不进入 artifact 上传。通过后删除 private 目录；失败保留以便诊断。

这些小库本机合同不证明默认 10 GiB 的本次重验、跨 AZ、AWS Standard、hard RSS、公平调度性能或生产 SLO。GiB 验收使用独立 [object-capacity](../object-capacity/README.md)；名称目录、自动路由、GC/PITR 仍有单独门禁。
