# 普通 `/v1` 输出池的真实慢消费者合同

这是独立、固定输入的资源正确性验收，不是吞吐基准或 RSS 上限证明。
正式 `scapd`、固定 Node SDK、native SQLite 和要求签名的 SeaweedFS 4.51
处理所有数据库操作。夹具只控制真实 TCP 消费速率和进程，不能访问私有 pool 计数。

## 冻结输入

- deployment=1；租户 A=7、B=8；数据库分别为 101、202；incarnation/generation=1。
- A 管理者 principal=11、A 另一已授权读者 principal=12、B 管理者 principal=22。
- worker_instance=5001。每次实验创建全新本机对象目录，随机测试凭据仅存 private。
- global output=256 MiB，保留 control=8 MiB；per-tenant=192 MiB，control=1 MiB。
- 大结果为单行 16 列 `zeroblob(2097152) AS b0..b15`，payload 共 32 MiB，
  每个值严格不超过 2 MiB，整体低于 50 MiB durable result 上限。
- 3 个 A 响应和 1 个 B 响应由独立真实 TCP socket 保持；connect 前设置
  `SO_RCVBUF=4096`，只读取 header，不读取任何 body。记录实际接收窗口设置、
 完整 header、Content-Length、请求正文和单调时间。每个 socket 有不可续期的整体期限。
- 显式 bounded transport 的 response_timeout_ms=120000、shutdown_timeout_ms=30000。
  baseline 配置只省略这两个尚不存在的字段，记录为单独 profile；不得把 baseline
  的结果解释成发送期限已经生效。max_connections=64，保留正常控制请求空间。

32 MiB wire 的 Base64 和 JSON 各约 42.67 MiB。正式实现先释放 wire 再分配 JSON，
因此峰值为 max(wire+Base64, Base64+JSON)，加每个请求 64 KiB 基础信用。
两个已有 A 响应加第三个编码峰值低于 191 MiB；三个已有响应加第四个峰值超过它。
三个 A 响应加 B 第一个编码峰值低于 248 MiB；四个已有响应加 B 第二个峰值超过它。
这些只用于选择输入；判据来自实际结果，不读取或伪造服务 pool 用量。

## 固定顺序和判据

1. SDK create/activate 两库，A 建 `proof(id INTEGER PRIMARY KEY)`，授权 A 的读者。
   SDK 在任何压力前 prepare/save 唯一业务请求 id=2：INSERT 一条小行，RETURNING 16 列大结果。
2. 保持 A1、A2、A3 三个 HTTP 200 大响应；每条 body 必须仍未被夹具读取。
3. A 的另一个 principal 通过 SDK 发同一大 query，必须得到 HTTP 413 / LIMIT。
   principal 变化不能绕过同一租户总额。
4. 保持 B1 的 HTTP 200 大响应。B 第二个 SDK 大 query 必须 HTTP 413 / LIMIT，
   此时 B 自己的预算足够，跨租户总额成为阻止条件。
5. A 的小 status 通过 SDK 成功，证明大型数据响应未耗尽控制分区。
6. 使用压力前已保存的原请求，只发一次 INSERT。它必须返回 HTTP 503 /
   COMMITTED_BUT_UNAVAILABLE，并带与原 Scope/Request 一致的可信 receipt。
7. 主动断开 A1（TCP RST），记录真实断开。新 A query 必须成功；它不能替代前述失败记录。
   其余 A2、A3、B1 开始消费到完整 Content-Length，独立核对全部 BLOB 字节；
   A1 只证明 header/holding/disconnect，不把它记为完整成功响应。
8. SDK 以原请求 lookup，必须取得 committed、同一完整 receipt 和完整 32 MiB 原结果。
   SDK COUNT 查询结果必须为 1。全轨迹中原业务 INSERT HTTP execute 恰好一次，禁止重放 SQL。

## 证据和独立判定

每次 HTTP 请求与响应正文保存为独立原始文件，账本只引用路径/长度/摘要，不把大 body
反复 Base64 塞入日志。SDK 输出保留 receipt 和解码摘要；独立 oracle 自己读取 raw body、
严格解码 SCAPRES1、验证全部 16 个 BLOB、重算 SQL 指纹和 Result envelope 哈希。
oracle 核对 S3 实际条件发布/回读、hold 的时间区间、原执行次数及 COUNT=1，
不接受 runner 汇总中的 PASS 作为证明。

正式 build receipt 绑定二进制所属的 source_root；新夹具的源码清单单独冻结并在末尾核对。
允许用不包含新夹具的既有 frozen binary 运行，但必须显式同时保留两组身份，
不改 build receipt、不复制新夹具伪装成旧源码。

至少提供篡改 LIMIT、principal/tenant、业务执行次数、CBU receipt、hold 区间、
恢复 BLOB/COUNT 与缺失对象发布等反例；各负控必须触发明确规则。保留原失败，
修正后使用新证据目录重新执行，不重新标记旧结果。所有 child 由原 Popen wait4 回收，
listener 关闭/join，private 凭据/缓存不进入公开归档。AWS、生产延迟/吞吐 SLO、
hard RSS、全局对象解码池、所有 HTTP 路由输出均不由本合同证明。
