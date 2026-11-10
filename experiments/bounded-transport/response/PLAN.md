# 真实响应期限合同（执行前固定）

本夹具装配正式未插桩 `scapd`、原生 SQLite、正式 Node SDK、真实 SeaweedFS S3，
通过原始 TCP 慢消费者验证发送期限，不读取或改写产品内部计数。它与 LLVM 单元覆盖分开。

固定候选 transport：8 connections、5000 ms header、2000 ms response、500 ms shutdown。
每个慢响应包含 8 列 2 MiB `zeroblob`，服务端 JSON 超过 21 MiB；客户端接收缓冲设为
4096 字节，逐字节只读完响应头后停止接收正文。默认 Linux 会将 SO_RCVBUF 加倍；
记录实际值并要求它在 4096..16384 范围。socket、请求身份、原始正文及单调时序全部落盘。

固定顺序：

1. `stalled`：大查询收到 200 头后停止读，头后 2300 ms 开始 drain，必须由服务端 EOF
   或 reset 截断，不能完整。再经正式 SDK 完成健康强查询。
2. `drip`：大查询收到 200 头后分别在 500/1000/1500 ms 读一个字节，头后 2300 ms
   开始 drain，仍必须截断。drip 原始字节单独保存，oracle 计算全部已收到正文。
3. `committed`：执行一次预先保存身份的 `INSERT ... RETURNING`，同样等待并观察截断。
   然后仅 lookup 原身份，检查原始结果 hash、完整零字节、receipt、S3 HEAD CAS、结果对象
   readback 和 `COUNT(*) = 1`；不得重放原 SQL。响应截断不等于事务取消。
4. `shutdown`：再保持一个大查询响应，SIGINT 后 owned wait4 回收 daemon，预期 0.5 秒
   连接关闭窗口（验收 0.3..1.8 秒，真实调度容差），随后 drain 必须截断且退出码 0。
   这只覆盖已完成数据库工作的响应；不声称不合作的 native worker 整进程退出有界。

对于前三项，drain 必须在响应头后 2.1..2.7 秒启动，并在启动后 2 秒内观察服务端截断。
本时序窗口只是该本地合同的调度容差，不能当生产延迟 SLO。不能以客户端主动 close/RST
代替 server expiry；失败清理记录与正常证据严格分开。socket 的发送完成不保证客户端应用
已经收到；完整结果只接受实际读到并按正式协议解析的字节。

新候选使用 bounded profile。baseline 模式仅省略旧版本不认识的两个字段；同一期限 oracle
应拒绝旧版本返回的完整慢响应，保存失败证据，不将 baseline 当通过。

启动前保存 fixture 源码 archive/hash、PLAN hash、正式 release build receipt、源码 manifest、
二进制/native archive 身份及配置。所有节点与服务 owned child 均 wait4，私有后端全部回收。
独立 oracle 从原始请求、响应、S3 history、时间和 wait4 判定，不信任 runner 的 success。
不证明 AWS S3 Standard 云端合同、总 RSS、持续吞吐 SLO、多进程共享 SQLite 文件安全、GC、
自动 owner 恢复或 PITR。失败原始目录保留；改代码后使用新的 evidence 目录重测。
