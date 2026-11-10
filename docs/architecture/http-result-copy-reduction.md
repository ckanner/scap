# HTTP 结果副本缩减

本切片只调整结果表示的所有权和序列化包装，基于 HEAD5 组合 `4329f30`。
它没有增加全局输出池、修改结果上限或改变请求的派发规则。
验证状态见[冻结记录](../evidence/http-result-copy-local-2026-11-09.json)；
当前编译、单元、覆盖率和实际 HTTP/S3 尚未执行。

## 问题与改动

大结果经过 SCAPRES1 编码和 Base64 后，旧 `json!` 表达式又通过
`serde_json::to_value(&value)` 复制 String；HTTP 成功包装还会复制完整 Value 图。
大量并行数据库或慢客户端会延长这些分配的存活，现有请求 body 额度和
单次 typed-result 预算都不能当成这些输出分配的全局上限。

`engine::committed`、`engine::queried` 和 `wire::resolved(Committed)`
现在把编码 String 直接移动到 `Value::String`，再加入原有字段的 Map。
`wire::Success<T>` 是 crate-private 的 Serialize 包装，按 `ok`、`value` 顺序
写入原成功 envelope。普通与 catalogue HTTP 出口移动拥有的 Value；
discovery 序列化借用的 Value。两种路径都避免再构造一棵成功包装的 Value 图。

公开字段、Map 排序、Base64、SCAPRES1 和 Engine/Worker 返回类型保持原合同。
discovery 仍先完整序列化，再执行原长度检查和原 deadline 检查；
原失败、UNKNOWN、COMMITTED_BUT_UNAVAILABLE 与提交回执语义不变。

## 回归边界

新增单元源码与固定 compact JSON 字节比较，覆盖引号、反斜杠、换行、中文、
空数组及 Base64。owned 与 borrowed 包装分别对照固定字节；owned 包装还
核对原 String backing 指针。不是用两份同一序列化实现互相充当 oracle。
此处记录的首次切片冻结时只完成静态审查；其后在 `778a4d2` 组合中通过完整
workspace 单位门禁，见[原始完整单位回执](https://github.com/ckanner/scap/blob/39b08c4f6705bde55e379a83250c4c47b598429f/docs/evidence/head5-runtime-workspace-local-2026-11-09.json)。
更新的编码基础另有源码和门禁，不能继承这份通过结果。

## 后续输出预算

此片仍保留现有 SCAPRES1 Vec、Base64 和 Axum JSON writer 的分配方式，
不能据此声称输出已全局有界、allocator OOM 已消除或吞吐已经测定。

后续预算必须在实际分配或增长前非阻塞取得额度，并同时计算新旧缓冲的重叠。
派发前应保留能够报告可信 receipt/error 的小额度；不能让每个小 INSERT 都
预留最大 64 MiB 结果的整个表示峰值，否则少数大额度槽位会限制独立数据库的并行。
已确认提交后的增长拒绝必须保留原 receipt 并返回原 CBU 语义，不得报告
执行前 BACKPRESSURE 或重放 SQL。全局和租户额度、Job/响应/最后 Bytes owner
的存活、共享 codec 可失败增长接口与慢输出合同仍需单独设计和验收。

## 源码依据

- 本库：`crates/scap-service/src/engine.rs`、`wire.rs`、`http.rs`、`discovery.rs`。
- 固定 serde_json 1.0.145 的 [`json!` 宏](https://github.com/serde-rs/json/blob/v1.0.145/src/macros.rs)
  与 [`Value` 序列化](https://github.com/serde-rs/json/blob/v1.0.145/src/value/ser.rs)。

编码基础与后续池的具体实现边界、按实际长度计费、已提交结果失败及最后 Bytes
所有权设计见[结果编码与服务输出预算](result-output-budget.md)。
