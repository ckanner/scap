# Guarded status：实际接收实例、权限和失效路由验收

## 固定目标与恢复边界

本实验装配正式 `scapd`、Node SDK、native SQLite 与签名 S3 TCP。输入在编写执行器前固定于
`inputs.json`。旧环境中未执行的输入和实现已经不可读；这里从已记录的30命令合同重建，
**不声称恢复了旧输入字节或旧实际测试结果**。输入明确保留旧 SHA 作为失踪检查点标识。
准备过程改用两个显式拥有并 `wait4` 的版本检查进程，以及进程内有界 SigV4 readiness；
没有隐藏 curl 或替代 daemon。30命令、29次 POST、原超时与故障目的保持不变。

S/P/Q 接收实例分别为9101/9202/9303，Scope为1/7/3101/1/1。S创建、激活、执行唯一SQL
身份(1,1)、授予测试权限，形成revision4；后续撤回 reader 的 READ 形成revision5。
P/Q只读HEAD，不能恢复SQLite或读取不可变数据对象。`guarded status` 的成功只证明接收实例
匹配、当前 READ 和这次 HEAD，不证明该实例拥有数据库或完整数据恢复成功。

## 必须实际观察的行为

1. 无guard兼容；非owner的正确guard成功；OwnerClient复制原可信registry，修改调用方原数组
   不改变已构造client的目标。不存在的worker不发送HTTP。
2. 错误worker在S3和cache前拒绝。null、0、前导零、JSON数字、溢出拒绝；最大u64规范输入
   按身份不匹配拒绝。无效token与跨tenant准入先于worker核对。
3. 撤回READ后，原reader即使命中相同端点也被fresh HEAD拒绝；ADMIN不自动授予READ。
   错误worker仍在S3前拒绝，manager在新HEAD上成功。
4. 实际S3 GET在转发前被黑洞一次，服务返回UNKNOWN；200响应在relay丢弃一次，SDK保留
   TRANSPORT；200响应被持有至原250ms绝对期限，SDK保留DEADLINE。三者均不能触发fallback、
   新路由、owner mutation或SQL重放。
5. 真实kill P并wait4，删除P私有cache，再在同一daemon端口启动Q。保留原HTTP relay与原
   已构造OwnerClient；旧P身份必须TARGET_MISMATCH且Q零S3。只有显式新S/Q registry才能
   probe Q成功，legacy status也能成功。P/Q的全部cache快照为空。
6. S最后lookup唯一原SQL身份，原Committed receipt及结果字节不变；查询只有原始一行。
   HEAD只发生五次预定发布，P/Q终生零PUT、零不可变对象访问。

## 分母、期限与资源

全部命令固定顺序执行：S七POST、P/Q共享HTTP slot二十二POST，unroutable零POST。
P九HEAD GET（八次真实转发与一次黑洞），Q两HEAD GET。三个fault各使用一次。
八个workload子进程=四个backend、S/P/Q三个daemon、一个Node；另有两个版本检查子进程，
所有均由实际Popen与wait4绑定。六listener全部关闭、serve线程和handler全部join。
固定bounds与deadline见输入，不因失败续期，不追加写入、不减少既定命令。

后端setup有独立40s、80round上限，每个请求至多1s且沿用剩余setup期限。daemon readiness
20s；正常service15s、recovery30s、S310s；SDK普通20s/recovery35s；短probe250ms。
whole-run300s。body、并发handler、累计handler、trace事件与字节均有上限。
成功与失败均保留私有backend/cache，结果只发布无凭据的摘要及身份；日志不得提交到仓库。

## 独立审计与完成条件

执行器记录原HTTP、原HEAD body/ETag、immutable frames、SDK body和original Fetch，分别绑定
源码、release executable及native archive。独立oracle只读这些证据和wire审计模块，不导入
执行器/SDK/产品；它独立固定30命令矩阵和原SQL/权限，不信任runner给出的PASS字段。

先检查完整分母、固定输入和字节，再检查同一次GET body/ETag、S3条件发布依赖、权限与故障
因果、lookup receipt、原SQL结果和process/listener退出。成功status不能替代数据闭包验证。
独立negative controls必须拒绝丢失/新增请求、错误guard或权限、偷换route/HEAD、假进程退出、
错误deadline因果与原receipt改写；原始完整副本positive control必须通过。

阶段状态：输入已固定；实现/静态审阅/fixture单位/真实运行/oracle/controls分别记录。
缺失阶段保持NOT_RUN。该实验不证明自动故障转移、生产吞吐或AWS Standard合同。
