# scap-engine

正式物理引擎的权威恢复包装。页面编码、摘要、prepare/accepted 与 receipt 重放复用 `scap_core::physical`；本 crate 负责把物理 image 绑定到 cell 的当前权限、位置和数据库 head。

`Image::recover` 要求调用者提供同一次可信 Store 读取的 CellState、完整 cell/database 身份、持久 applied 和目标 revision/commit hash。它先校验这些边界，再调用当前 READ admission 下的 `CellState::recovery_source`。Cold 状态拒绝恢复，不能改读旧本地缓存或未核验的对象。

有合法基线时，先用共享算法校验并装入完整 image，再重放连续 tail；无基线时从空镜像重放 tail。基线的 source position 与逻辑前缀由经过校验的 CellState 绑定，image digest 仅证明 bytes。恢复不要求或允许把已退休的物理前缀伪装为仍可从 revision 0 重放的历史。

公共的 `Image::empty/head/bytes/limits/prepare`、`Prepared::write/accepted` 和原错误语义保留。没有修改 native WAL publication 的顺序：只有可信的精确持久接受 receipt 才能授权发布。原结果查询仍由 cell Lookup 返回，与物理 tail 是否已折叠无关。

格式、旧数据升级、通信世代与容量边界见 [ADR-0017](../../docs/adr/0017-bounded-physical-history.md)。本地新目录恢复、真实提交前后崩溃、snapshot 与 S3 验证属于独立故障实验，不能混入单元覆盖率。
