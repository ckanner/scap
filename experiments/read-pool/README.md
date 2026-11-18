# 同库读池的实际合同

本夹具启动正式 `scapd`、原 Node SDK 和固定 SeaweedFS 4.51；复用现有完整 HTTP／S3
字节代理，保存原始请求、响应、HEAD body／ETag 和 owned 子进程身份。它不是单位
覆盖，也不认证 AWS、生产 TPS、RSS 硬上限或 lazy VFS。

运行前冻结源码并用 `experiments/object-service/build.py` 产生正式 release receipt。
执行入口为 `run.py --binary ... --build-record ... --weed ... --node ... --evidence ...`。
证据目录必须新建，原失败保留；`oracle.py` 只读复核完整原始记录。
`source.json`／`source.tar` 保存完整 tracked 源码，包括本夹具与全部复用 helper，
`source-after.json` 证明执行期间未变。独立 oracle 同时核验原 release build archive、
实际配置、Node／SeaweedFS／scapd 二进制与 owned 进程退出记录。

## 固定合同

生产配置启用 3 个 read worker、每租户 2 个活跃读、每库 2 个活跃读。只使用两个
小数据库、主库固定三行整数数据和非确定原结果，工作量不随结果调整。

1. seed：两个租户分别创建、激活、提交原始数据，主库额外授予独立 reader READ。
2. overlap：同时阻塞主库两个 query 的真实 HEAD GET；两个请求必须在释放任何一个
   gate 之前到达不同 S3 请求。原单 actor 不能通过此条件。
3. fairness：第三个同租户 query 已送到服务并排队；另一租户的 query、主库的写和
   control status 必须在释放上述读 gate 之前完成。排队 query 不得越过活跃上限。
4. refresh：写入完成后释放读；读结果包含新提交的第二行。随后用另一租户的两个
   HEAD GET hold 占住两个 reader，剩余唯一 reader 执行 warm。再提交第三行，
   同一 reader 的 query 必须发出恰好三次 HEAD GET（stale 检查、重新恢复、新鲜
   query 检查）并返回三行，然后才释放另外两个 reader；冷 reader 不能代为通过。
5. failure：原 HEAD GET blackhole 返回 UNKNOWN；query 中的写语句被拒绝，均无写
   结果发布或客户端重试。撤销 reader READ 后，新 query 返回 DENIED。
6. receipts：三个非确定写事务按原 request identity lookup，原始结果和 receipt
   逐字匹配，证明读池与独立 writer 没有改变提交语义。
7. cleanup：验证活动镜像的 device／inode 不重用，私有 worker 目录不别名；正常
   SIGINT 后所有 owned worker 退出、缓存文件清理；不把 HTTP 请求结束当 native 退出。

独立 oracle 校验 SDK 每命令单次发送、真实 HTTP 回执与命令绑定、S3 原始字节与条件
写历史、两个 hold 的真实区间、writer／control／另一租户在区间内进展、第三 query
在 release 后完成、撤权与错误结果、原随机结果及资源清理。每一类判断配合定向
篡改的负控；这些负控不算新的故障执行。

工作量固定为 21 个 SDK 命令、27 次 HTTP POST。`controls.py` 包含 8 个完整原始证据
负控和 11 个区间投影负控，后者明确标为 projection，不冒充新的 S3 执行。运行器在
实际合同结束后依次执行原始 oracle 和负控；可用
`python3 -m unittest discover -s experiments/read-pool -p 'test_*.py'` 先检查 oracle 的
因果边界与 SDK 时钟格式，该检查不替代实际执行。

当前验收状态由交付报告及 CI 的精确候选决定，不从本说明推导 PASS。
