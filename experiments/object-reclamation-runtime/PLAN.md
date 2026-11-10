# HEAD6 compaction / GC 真实运行合同

状态：实现前计划，尚未运行。此目录只装配正式 native seed worker、`scapd`、Node SDK
与签名本地 S3；不实现第二套产品维护算法。执行前须冻结本目录、正式实现、SDK、全部
构建输入与本计划。每次失败保留原目录；任何输入变更使用新候选和新 evidence。

## 原始范围

固定 deployment=1、tenant=7、incarnation=1、logical generation=1。
数据库 4101 为三窗口复制与迟到对象，4102 为原 HEAD 候选与迟到删除，
4103 为 abandoned target 与 checkpoint 故障。所有 generation 下文均指物理 storage generation，
不改变逻辑 Scope。三个 Scope 的 root、请求、对象与故障不能混用。

初始正式服务 worker A=5101、B=5102，另一个独立冷 lookup 服务 R=5103；
seed worker 使用独立的4001–4003身份，回收后由A通过正式takeover/activate接管。
服务重启分配新的非复用worker身份，旧worker不能借重启恢复原dispatch资格。
每个服务具有独立 S3 观察 listener，转发至同一实际 backend。维护始终通过正式 HTTP
操作，SQL/lookup 使用正式 SDK；只有 seed 的固定 retention profile 使用既有正式
`experiments/object-network/src/main.rs` assembler。不存在 raw HEAD seed/改写。

普通存储与 GC 使用独立 credentials 和 env 名称。GC 配置显式 opt-in；
不启用 GC 的服务不能 DELETE。每个 DELETE 的实际签名身份必须与配置 GC 身份对应。
unsigned 实际请求必须被 backend 拒绝。fixture 不把本机兼容后端证明当 AWS IAM 或
AWS Standard 保证。

## 先于维护的独立 seed

4101 使用正式 native 配置 retention_entries=129、retention_result_bytes=268435456，
quota_bytes=67108864。窗口 1 的129条成功原 SQL 之后合法 close_full；窗口2同样129条
并 close_full；窗口3两条成功原 SQL及一个原身份 cancel。因此保留三个窗口，
260个成功 SQL 原请求、260份完整 receipt / SCAPRES1 及一份取消证明。
前两个窗口必须真实产生 Index branch / leaf split。SDK不能用新请求代替 seed 身份。

每次 SQL 的输入在 dispatch 前持久保存，ACK 在实际收到后记入独立账本。
保存全部原 SQL、参数、fingerprint、Scope、epoch/id/principal、receipt、完整 encoded result。
随机 RETURNING 只以外部原 ACK 原字节为恢复期望；不能从恢复后数据库反读生成期望值。
最终业务行的确定字段另由输入序列推导。seed worker 使用独立同源码 release receipt，
普通服务不能冒用它的构建记录。

4102、4103 使用小而固定的独立 seed。它们的全部 SQL 也有完整原输入/ACK；
不得通过 operator 改写 HEAD 制造满窗、active generation 或可删除状态。

## 核心成功判据

一次 copy 从原 plan.basis 的 current data_root、三个 retained window roots 遍历真实
SCAPOBJ2 bytes。独立 oracle 检查 Manifest / Node / Chunk 和所有 Index 子节点、
Committed Result；校验 Scope、hash、原始 frame、树聚合、范围与保留窗口条目。

Result.data_root 仅是原 receipt 身份，不沿它扩大历史 data 闭包。至少选择一个已不在
当前数据闭包中的历史 receipt data_root，证明其未成为目标复制义务；对应原 Result
仍完整保留。目标代际的每个闭包对象都必须经过正式 Absent PUT 和 exact readback
或已有相同内容的受控条件冲突+原字节回读，在 Seal / Promote 前核对。
不能仅信 SDK 状态或复制对象数量。

技术维护只推进 head_serial；业务 revision/transition、sequence、请求窗口、原结果、
quota 和 retention 按合同保持。明确 policy 操作可推进业务 revision/auth_epoch，
promotion 必须保留当前 ACL，不能恢复 Freeze 时的旧权限。
Promote 必须留下 inactive 新 generation；后续显式 takeover/activate 才恢复 SQL。
所有最终强读在实际清除 compute cache 后重新物化。

## 固定故障族

### A. 三窗口复制、旧读与迟到 PUT（4101）

1. 保存三窗口原 HEAD/全部 ACK。
2. 开始一个仅一次发送的旧 SQL，暂停其已发出的新 immutable PUT，在 backend 收到前持有。
   客户端原超时保持 UNKNOWN；不重放、不修改该请求的 key/body/If-None-Match。
3. B 用当前 exact HEAD serial 开始 plan，完成完整闭包 copy 和 Seal。
   期间用独立合法 policy 更新证明 ACL 不被 promotion 回滚。
4. Seal后、Promote前开始旧冷 lookup；它取得原 HEAD 后暂停一个 source-generation
   immutable GET，在真实backend收到前持有。再Promote到generation2，核对inactive、
   原逻辑身份、全部业务结果和取消屏障保持。
5. 对退休 generation 1 做首个有界批次：after固定为实际held hash的数值前驱，保证目标
   在首批至多32项中。第一份 checkpoint 完整持久后终止并回收维护服务，删除其本地
   compute cache，由新服务实例仅使用原 batch serial 恢复。prepare阶段不得 DELETE。
6. 首批完成后立即放行旧 GET，
   原 backend 缺失必须跟随一次新 exact HEAD 的严格退休证明，返回 SnapshotExpired；
   无权威、current/target 缺失、hash-valid语义坏均不能冒充过期。
   随后另从after=null逐页完整扫source代，不把首批frontier当完整轮扫描。
7. 放行原 immutable PUT，必须实际在退休 generation 1 成功重建 orphan。
   当时 generation 2 的完整闭包不变，旧 SQL 没有新成功 ACK 或新 HEAD 权威。
8. 新一轮从 after=null 起点扫描，找到并按新批次删除迟到 orphan。
   空页只表示这一轮观测，不宣称永久为空。
9. 全部 compute cache 丢失后显式接管/激活，逐条 lookup260份原 receipt/result，
   核对取消身份和最终业务数据，不重放任何已发送 SQL。

故障原客户端 deadline 不因暂停而延长；fixture 单独有有界等待/整体期限。
代理放行的迟到请求仍是原请求，不能替换成 operator 的新 PUT。
本profileS3/HTTP配置各120秒，SDK普通调用90秒；lookup core直接使用service传入的原
deadline，没有Options默认30秒clamp。夹具额外要求旧lookup从dispatch到实际expiry返回
小于30秒，仅作为本次观测边界；任何真实超时仍保留UNKNOWN失败，不能伪称产品30秒保证。

### B. 原 HEAD CAS fencing 与迟到 DELETE（4102）

1. 原 SQL 只执行一次，在它已上传并读回依赖后暂停原 HEAD PUT。
2. 独立维护先完成 Begin/Copy/Promote，随后放行原 HEAD PUT。
   backend 必须实际返回原 If-Match 的412；不能注入412、刷新ETag或再执行 SQL。
3. 退休代安装真实持久 checkpoint；在一个原条件 DELETE 到达 backend 前暂停。
   原 caller 截止/终止后，新维护进程从相同 checkpoint 恢复。
4. 新进程完成该 batch，随后完成下一次合法 copy/promotion。
   再放行迟到原 DELETE：只能携带旧 generation/key/ETag；
   即使新 active generation 存在同 hash/bytes，不能触及它。
5. 原未知调用不因后台效果改写成原 ACK；当前完整数据与所有原 retained result 保持。

### C. Aborted target、未知删除和原 ETag（4103）

1. 开始target plan并实际复制对象后合法 Abort。
   allocated_through不回退、target永久退休，active source保持受保护。
2. prepare持久保存原精确候选key/hash/ETag，没有DELETE；回收维护进程后重启。
3. 一个 DELETE 在 backend实际接受后丢响应，caller只能UNKNOWN，pending checkpoint不能清除。
4. 在旧 key 上重新创建同原bytes但不同backend ETag（用后端真实支持的multipart路径，
   先独立验证该能力；不能用代理改写 ETag 充当 backend事实）。
   原 batch 重入不得刷新ETag；必须真实DELETE原ETag并取得backend412，
   才可记录 condition_mismatch，不能仅因inspect看见新ETag就伪称412，也不能删除新版本。
   下一份独立 prepare 才能取得并使用新ETag。
5. 对已持久pending checkpoint的inspect GET注入完整404 NoSuchBucket，
   必须失败关闭、没有DELETE、checkpoint保持。清除故障后的正常typed NoSuchKey
   只能作为实际缺失观察，不能将缺bucket、generic404或transport unknown归为缺key。
6. 完成后用旧 batch serial 再调用必须Conflict。永久generation身份不复用。
   active generation与HEAD/Catalogue/逻辑身份屏障从未进入DELETE候选。

## 原始观察与独立 oracle

每个原 HTTP / native stdin 调用及终结都有完整raw bytes、hash、时序、身份与唯一序号。
所有实际 S3 GET/PUT/DELETE/LIST/config请求与backend结果、forward和delivery边界完整保存。
每个故障明确区分before backend、backend接受后响应丢失、fixture注入响应，
不能把代理发送、调用返回或runner PASS当backend线性化点。

新oracle独立核对HEAD6业务与技术状态链、A/M/plan/sweep、≤32项checkpoint、
原exact GET body/ETag、各disposition及fresh持久授权。它不调用旧
object_exchanges/object_versions接受GC，仅复用纯JSON/frame/SCAPRES解析工具。
GC DELETE必须严格落在已退休generation，先有相同checkpoint的持久CAS和fresh观察，
原key/ETag不可变。所有目标闭包对象与260份原结果逐字节比对。

候选源码manifest、正式service/native-seed两个release receipt、实际binary/native archive、
fixture源archive、Node/SeaweedFS工具摘要、原PLAN均在执行前后核验。
所有owned children按实际wait4回收，socket/proxy线程全部结束，cleanup错误不通过。
public证据不含bearer/secret；private运行目录与原始失败保留规则单列。
不得将该实际运行产生的任何profile加入unit覆盖。

## 负控与范围

实际通过目录的独立副本至少拒绝：缺失原调用、遗漏closed-window Result、
目标同hash不同bytes、提前Promote、将历史receipt data_root当复制根、删除active/target代、
无checkpoint DELETE、改用新ETag、UNKNOWN改为Applied/Absent、NoSuchBucket改为Missing、
漏掉迟到PUT、新轮不从起点扫描、把原412改成ACK、提前释放旧GET/DELETE、
重放原SQL、遗失或伪造owned wait4、缺少完整原结果。
每个反例必须命中预期语义边界，不以任意schema异常冒充通过；原样复制正控必须通过。

本合同不证明AWS Standard、吞吐SLO、无限持续垃圾收敛、PITR、retained snapshots、
自动owner controller或Deleted数据库最终active generation的回收。
Deleted最终A仍保留，不能伪称本切片已经物理删除全部数据库。
