# 受信动态 fleet：固定实际合同

本合同验证有限配置更新，不证明分布式 registry、自动扩缩容或生产 SLO。
冻结源码后只运行正式 release、Node 22.16.0 和带 SigV4 的 SeaweedFS；全部记录位于
源码外。原 180 秒全程、75 秒阶段预算保持，失败不覆盖、不延长预算后冒称原运行通过。

## 固定拓扑与业务

完整 Scope 为 deployment=1、tenant=7、database=8601、incarnation=1、generation=1。
三个初始 worker A=9601、B=9602、C=9603；一个替代进程 D=9604 在 A 已退出后使用
A 原 HTTP 入口与新的私有缓存目录。A/B/C 的完整原始 HTTP 和签名 S3 代理、四个
owned 后端进程、正式构建 receipt 与完整源码档案均使用已有观察器。

原业务只 execute 三个保存身份；前两个收到 ACK，第三个真实服务已提交但 HTTP 回复被
丢弃，业务获得 UNKNOWN。SQL 含计数器、randomblob 和 random，最终从 D 用原身份
lookup 三个结果并逐字比较，查询计数器仍为3，保留的 HEAD9 快照仍为 sequence=2。
所有控制器调用的主体为12；它不得发送 execute/query 或其他业务 API。

## 固定更新序列

1. v2配置revision=1，policy P1含A/B，metadata入口C。A健康时只读。
2. revision=2，P2在P1基础上增加C并显式退役A。新目标B通过实际guarded status；
   prepare和claim沿原输入，B的claim成功回复丢失，控制器记录UNKNOWN。
3. revision=3，P3保留P1/P2完整历史并退役B。新controller必须inspect原P2计划并
   abort原reference；禁止claim/resume已退役B。随后新P3计划让C接管并完整恢复。
   在线reload保留旧UNKNOWN，不能把C后来Active称为原B调用收到ACK。
4. revision=4，P4增加rank更高的D、退役C，并显式把已退役A的入口绑定给D。
   此时入口实际仍是A，必须得到TARGET_MISMATCH且零owner mutation，禁止改写guard。
5. 等待A实际退出并删除原cache，启动永久新身份D，保留A原入口。revision=5沿用
   同一P4完整history；新目标D重新guarded核验，再prepare/claim/resume。D为独立
   新进程与空缓存，必须从原S3数据恢复；原B计划不重发。
6. 尝试回退至revision=2，然后尝试revision=6但让已退役C复活。两次reload均拒绝，
   当前revision保持5；原完整配置和拒绝报告均保存。
7. 当前ADMIN撤回主体12权限，控制器fresh status得到DENIED；不得继续mutation。
8. SIGTERM并join控制器后，业务在D验证全部原结果、数据和快照。向复用入口发送A
   原guard仍返回TARGET_MISMATCH且无S3副作用。退出所有owned资源与后端。

## 独立审计出口

- 所有HTTP/S3原始请求/响应、签名摘要、条件、HEAD候选原ETag、owner descriptor、
  owner phase、实际status投影和worker永久登记需闭合；controller日志不构成权威。
- P1–P4的完整canonical/nonce由独立Python逻辑从原配置重建；历史只用于验证原计划。
- 固定owner mutation总数：prepare3、claim3、resume2、abort1。P2/B只有claim，
  原claim回复丢失后只inspect/abort；P3/C和P4/D各一套新身份的prepare/claim/resume。
- 原始来源、正式构建完整输入、真实工具、Node入口、启动前时刻、worker登记、owned
  wait4、实际cache删除及全部listener关闭要逐项绑定。所有旧失败原样保留。
- 定向反例至少覆盖：guard替换、退役目标resume、旧recipe修改、漏history、配置回退
  接受、复活接受、UNKNOWN消失、SQL重放、错误最终结果、原HEAD条件刷新、source
  不完整与owned进程退出缺失。反例修改观察投影或隔离副本；不得修改实际原件。

本地兼容S3结果不能替代AWS Standard、IAM、云故障域、真实NFS挂载或生产SLO。

