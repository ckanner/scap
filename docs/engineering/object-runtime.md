# 对象原生运行时 v1

主入口是 `scap_object::Database`，用 `Arc<dyn scap_object_store::Objects>`、不可变 Scope 和非零 worker identity 装配。S3 adapter拥有自己的异步runtime，给独立阻塞SQL线程提供同步对象port；不可从同一异步executor直接阻塞调用。

## 权威与数据布局

HEAD key固定绑定deployment/tenant/database；incarnation和authority generation放入body，每次读取校验，禁止通过换key复活旧数据库。不可变对象key同时包含全部scope和SHA-256摘要。GET的ETag仅是opaque比较令牌，不作为内容摘要。

HEAD包含当前revision/transition、SQL sequence、owner、policy、lifecycle、data root和三个以内的世代索引root。原始JSON整数是内部持久格式的u64；未来JavaScript网络协议须使用无损整数编码，不能直接转为Number。

| 预算 | 值 |
| --- | ---: |
| 页大小 / 页数 | 4096字节 / 64 |
| HEAD编码 | 16KiB |
| 单不可变对象编码 | 512KiB |
| SQL/原结果 | 16KiB / 64KiB |
| 单事务语句 / 参数 / 列 / 行 | 32 / 每语句128 / 64 / 共1024 |
| 单值 | 16KiB |
| 当前世代终态 / 保留closed世代 | 128 / 2 |
| policy主体 | 16 |

JSON字节数组按最坏膨胀计算；所有编码与解码均检查实际wire长度。数据库映像由不可变页面恢复并核对整体摘要。请求索引绑定epoch/id、原principal和精确SQL指纹；同ID更换主体/参数被拒绝。

<a id="recovery-closure"></a>
### 当前恢复闭包

发布和激活校验的闭包包含当前HEAD数据根的Manifest及全部Page，以及所有保留窗口的Index和对应Result对象。`StoredResult.data_root`保存原提交receipt中的数据根标识，用于返回原始凭据；它不提供历史快照读取或PITR入口，当前恢复不会继续遍历每个旧根的Manifest/Page。当前没有历史读取或对象物理GC；历史保留根、pin、PITR和GC的依赖范围仍须在N3独立设计与验收。

## 操作

- `create`：显式初始化；只条件创建HEAD，失败或既有库404不自动创建新库。初始writer处于Recovering。
- `takeover` / `activate`：当前管理权限与原revision，增加owner epoch；恢复所有页面与保留结果后，重新核对HEAD才能激活。
- `execute`：先校验当前权限和原请求。已提交时返回原结果；未查证的新操作进入私有SQL与precommit gate。任何自动SQL重试均禁止。
- `query`：新鲜HEAD、当前READ权限、单个固定快照；不依赖writer本地文件或owner租约。
- `lookup`：未知、已取消、原结果、closed、retired各自保留语义。absent不是取消证明。
- `cancel`：取消和数据提交竞争同一HEAD；没有成功CAS不返回cancelled。
- `close_full`：当前窗口满后才有序关闭，保留两代完整结果；不承诺最低时间留存。该内部操作不删除对象。
- `set_policy` / `set_lifecycle`：同一HEAD上修改权限、维护与删除；Deleted拒绝后续操作，保留对象与身份屏障。

## 准入与部署边界

本轮Rust API假设调用方已经鉴权，`principal`不能从未认证的外部请求直接复制。S3凭据必须只授予可信协议进程，不能分发给租户。外部用户网关、动态目录、SDK、每租户调度、部署密钥轮转在N2/N4完成。

所有操作继承调用方的同一个绝对deadline，存储适配器不自动重试。条件失败仅描述本次CAS；网络错误或成功响应丢失不证明业务未提交。CAS后local publish失败返回CommittedButUnavailable，原结果可从对象查证。

当前每次执行从完整小型权威映像重建私有目录，性能未经生产验收。页面上传为增量；下载、页映射编码和结果索引仍有放大。更大库和公平缓存应另做验证，不能调大常数即宣称扩容完成。
