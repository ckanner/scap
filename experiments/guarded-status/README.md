# Guarded status 的实际传输验收

该实验针对[正式 guard 合同](../../docs/architecture/owner-guarded-status.md)，
覆盖正确/错误接收实例、fresh READ、故障响应、原绝对期限和端点被替换后的旧registry。
输入和预先限定的范围见 [PLAN](PLAN.md) 与 [inputs.json](inputs.json)。

## 当前状态

冻结生产候选 `d60ea98eab8d073cfe118f3176c41ba6e2a4ab02` 已完成本合同：
fixture 单位、真实运行、独立 oracle、31 个语义负控和完整副本正控全部通过。
30 个原操作/29 个 POST、46 次 signed S3、五次 HEAD 发布和唯一 SQL 执行身份均由
原始账本核对。该结果只认证此冻结候选，不自动认证后续 HEAD6。
完整来源和先前失败见[组合验收](../../docs/engineering/runtime-completion-validation.md)。

该程序固定30个操作/29个POST、三个一次性故障、五次HEAD发布和唯一SQL执行身份。
P/Q的完整S3流量只能是HEAD GET；错误guard不能触碰S3、SQLite payload或旧cache。
替换必须真实kill/wait4 P、删除其cache，再在同一端口启动具有新identity的Q。
SDK保留此前已构造的OwnerClient，不能用重新构造的client冒充旧registry测试。

## 运行

先按仓库固定环境构建并保存 `experiments/object-service/build.py` 的release回执。
这里的服务binary及native archive必须与该build回执精确匹配。fixture源另在实际运行前后绑定，
实际证据目录、控制副本与私有backend/cache放在仓库外，推荐空间充足的本地磁盘。

```sh
python3 -B -m unittest discover -s experiments/guarded-status -p test_support.py -v
python3 experiments/guarded-status/run.py \
  --server /absolute/release/scapd \
  --weed /absolute/tools/weed \
  --build-record /absolute/build/build.json \
  --evidence /absolute/evidence/guarded-status
python3 experiments/guarded-status/oracle.py \
  --evidence /absolute/evidence/guarded-status \
  --output /absolute/evidence/guarded-status-oracle.json
python3 experiments/guarded-status/controls.py \
  --evidence /absolute/evidence/guarded-status \
  --output /absolute/evidence/guarded-status-controls
```

执行器成功只写 `OBSERVED_NOT_AUDITED`；oracle成功和controls成功各有独立输出。
oracle重新读取原POST、SDK Fetch、同一次S3 GET body/ETag、每个完整依赖及HEAD条件链，
核对原SQL receipt、固定查询结果、readback-before-publication和全部owned child/listener退出。
只读取已完成的证据，不重试产品操作，不从runner的成功标记推导协议正确性。

31个负控针对请求删减/追加、guard或身份被改、跟随不可信地址、错误目标访问S3、stale ACL、
body/ETag错配、metadata路径写S3、伪造wait4、worker identity复用、旧client重建、期限提前释放、
UNKNOWN被升级、原receipt改写、payload cache、错误binary和handler未join。
它们也检查实际接收进程/监听器的生命周期、Node时钟、fault原请求与hold切点；每个变体
必须命中预先声明的确切拒绝规则，不能用无关schema或分母失败替代目标边界。
每个控制只修改审计投影，原实际证据逐文件哈希保持不变；完整原证据复制后必须再次通过oracle。

观察器另外定义五个边界单测：日志写入失败后真实 Service/Node 子进程仍被登记并wait4、
已启动listener仍关闭并join、超长未结束Node输出行在解析前受限，以及缓慢分段输入不能
刷新原socket绝对期限。它们验证测试设施的失败路径，不能代替上述实际30命令合同。
记录失败具有持续状态；清理继续执行，最终结果必须失败。whole-run原300秒包含清理时间，
不会因为清理延长而记录成功。

## 结果解释

status成功返回的是原HEAD与当前READ。它不证明完整payload健康，也不触发恢复、takeover、
activate或SQL。该验收不证明自动故障转移、生产吞吐、全进程RSS或AWS云端合同。
两个版本检查进程与八个workload子进程分别列明，均由Popen/wait4绑定；没有隐藏readiness子进程。
所有准备动作有固定范围，成功/失败都保留私有backend/cache，原始运行日志不提交到Git。
