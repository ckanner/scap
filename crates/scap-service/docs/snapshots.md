# HEAD9 S1：显式保留快照接口

状态：实现候选。单元、模型、真实 HTTP/S3 和生产门禁分别记录；不能把有界模型通过当成服务验收。新 Scope 恢复属于 S2，本接口没有导出或恢复数据库的入口，也没有任意时间点 PITR。

## 权威与生命周期

所有操作使用认证 `POST /v1`，带 `version:1` 和完整五元组 `scope`。认证主体来自可信 bearer 配置，creator 只是永久操作身份的一部分。每次重新检查当前 HEAD 权限。控制元数据走 control 准入，不创建本地 SQLite Session。

| operation | 严格附加字段 | 权限与效果 |
| --- | --- | --- |
| `snapshot_prepare` | `input:{creator,operation,expected_revision,expected_head_serial,label}` | ADMIN+READ；固定原始 HEAD/ETag、根、页数和初始限额，保存永久 first-winner descriptor |
| `snapshot_inspect` | `identity:{creator,operation}` | ADMIN；读取真实 descriptor、fresh HEAD 和必要的永久 accepted proof |
| `snapshot_capture` | `reference:{creator,operation,capture_serial,descriptor_hash}` | ADMIN+READ；向 descriptor 的原 HEAD/ETag 发布一次，或观察已存在的相同点 |
| `snapshot_release` | 同一个完整 `reference` | ADMIN；先保存 accepted proof，再以当前原 ETag 移除同一点；每次调用至多一次 HEAD CAS |
| `snapshot_list` | 无 | ADMIN；返回该 HEAD 的有界 live 列表和持久 limits |
| `snapshot_limits` | `expected_revision,nonce,limits:{max_points,max_logical_bytes}` | ADMIN；原 revision 的业务 CAS，限额必须容纳已有点 |

u64 全用规范十进制字符串。`page_count` 与 `max_points` 使用 JSON 整数：前者至多4,294,967,294，后者0–64。label非空、至多128个UTF-8字节、无控制字符。prepare不接受客户端自报的root或页数，后端从当前已提交Manifest获取。

capture/release只推进物理`head_serial`，保留业务revision/transition、sequence、owner、数据根和请求结果。limits推进业务revision/transition和物理serial。这些元数据操作不驱逐有效的本地SQL Session；后续每次SQL仍重新查HEAD。

新prepare/capture要求Ready、无pending owner、COPY、sweep或terminal。已知身份的metadata查证可在后续状态读取。release允许Deleted，不能在pending owner/COPY/sweep中移除root。限额变更仅限Ready/Maintenance且没有维护计划。正常删除不会暗中丢弃快照；最后一点release以前不能安装terminal retirement。已有terminal不开放新payload context。

## 响应与 UNKNOWN

prepare返回`{scope,input,reference,point}`，其中point为`{data_root,page_count,sequence,source_revision}`。capture/release/inspect返回`{state,status,prepared,accepted}`：status是现有完整投影，prepared是原descriptor的公开投影，accepted是`{reference,label,point}`或null。

状态包括`prepared`、`retained`、`released_observed`、`fenced`。fenced且无accepted不证明过去从未接受。released_observed表示当前稳定HEAD已不持有该点且有确切accepted proof，不是对过去超时调用补发ACK。list/limits返回`{status,snapshots,limits}`；旧HEAD尚未采用快照格式时为`[]`和null。

prepare/capture/release/limits的断连、deadline或无法验证成功响应保留UNKNOWN。客户端必须保留原输入和完整ref，不能刷新expected revision/serial重新定义原operation，也不能按label重新选点。另一个当前ADMIN可查证身份，永久descriptor不授予历史权限。

## 空间、恢复与复制

默认live上限64点、gross逻辑空间32GiB。gross按每点完整逻辑页数累计；共享对象不抵扣该策略额度。当前业务quota不重新判定历史点是否合法。每个不同prepare永久占据descriptor槽；曾接受的点释放时还永久保存proof。live列表有界不代表bucket控制对象总量有界。

完整恢复验证当前数据、所有保留根和请求结果，依赖缺失/损坏失败关闭。COPY固定完整列表和限额，逐树验证页数/节点/块并搬到新物理代；全部闭包完成才能promote。旧代GC不会删除新代仍持有的快照数据。descriptor/proof位于永久控制前缀，不由payload GC删除。

S1要求`restore_origin`显式为null。解码器拒绝非空恢复状态，避免旧Catalogue空库创建路径把未完成导入当成Ready。新Scope恢复的权限、CompletionRecord、取消屏障和重封装见[完整设计](../../../docs/architecture/retained-snapshot-restore.md)。
