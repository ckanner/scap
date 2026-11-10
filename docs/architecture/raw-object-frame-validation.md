# 借用原始对象帧的校验层

本层只整理现有 `SCAPOBJ2` 解码：在复制 Chunk 或 Result 的 raw payload 之前，校验原始帧的哈希、完整逻辑 `Scope`、类型、长度和该对象自身的结构约束。对象格式、哈希算法、公开的 `decode_object` 返回类型与错误分类不变；它不启用多物理世代、pin、freeze、copy、GC 或维护接口。

实现位于 [object_frame.rs](../../crates/scap-object/src/object_frame.rs)，与 [format.rs](../../crates/scap-object/src/format.rs) 的 `Envelope` 规则共用语义校验函数。`ValidatedFrame<'a>` 是内部类型，保留输入 `&'a [u8]` 和已解码的有界 JSON metadata。metadata 中的 Chunk/Result `bytes` 必须是空数组；真正的 raw payload 继续借用原输入。它没有修改原始帧、重新解析或重新生成原始哈希的接口。

## 校验与转换顺序

`parse` 先检查现有的总帧上限，再验证整个输入的 SHA-256。随后检查固定帧头、magic、metadata 长度、raw 长度以及无截断、无尾随字节的精确总长度。只有这些检查通过，才反序列化 metadata。

同一个语义校验函数同时用于编码 owned `Envelope` 和校验借用帧。编码路径传入已有 raw Vec 的长度；借用路径传入帧声明且已与实际输入核对的 raw 长度。因此 Chunk 的页对齐、最大长度、末页范围以及 Result 的长度上限不需要先复制 raw 数据。Node、Manifest、Result 请求身份和 Index 的既有本对象约束仍会检查；完整 `Scope` 的五个字段必须与调用者传入的预期身份相等。

`as_bytes()` 返回确切的原始帧，而非重新序列化的内容。合法 JSON 可以有不同字段顺序、空白和转义；即使它们解码成相同 metadata，原始帧和 SHA-256 也可能不同。`into_envelope()` 消费已经校验的帧，从这个 accessor 获得原始 raw 切片，仅在此处复制 Chunk/Result 的 raw 数据，返回原来完全 owned 的 `Envelope`。公开 `decode_object` 直接组合这两个步骤。

成功的现有 owned 解码仍需要一次 raw payload 复制；这次调整不会宣称取消它。其收益是让 raw 数据在所有拒绝检查完成之前保持借用，并为只需要原始帧的内部校验保留字节身份。JSON metadata 仍有分配，metadata 输入上限仍为 `64 KiB - 20 bytes`；这不是无分配解码，也不是整个进程的 RSS 上限。

## 保持的拒绝合同

| 输入或条件 | 结果 |
| --- | --- |
| 输入总长超过既有 `MAX_OBJECT_BYTES` | `FormatError::Limit`，优先于哈希等其他检查 |
| 哈希、magic、固定帧头、metadata/raw 长度或精确总长错误 | `FormatError::Corrupt` |
| 缺失、重复、未知或类型错误的 metadata 字段 | `FormatError::Corrupt` |
| Chunk/Result 的嵌入 `bytes` 非空，或其他类型附带 raw 字节 | `FormatError::Corrupt` |
| 本对象结构或完整预期 `Scope` 不符 | `FormatError::Corrupt` |
| 合法但非规范化的 JSON 表示 | 接受且保留原始字节；不替换为重新编码版本 |

编码路径已有的 `Invalid` 与 `Limit` 区分继续由同一套 `Envelope` 检查产生。未扩大任何格式或业务上限。空 Result raw payload 仍可通过对象帧校验；是否为合法 retained SQL result 是另一个层次的问题。

## 这个结果不能证明什么

帧校验只证明单个给定输入符合本对象格式并匹配调用者给定的哈希和 `Scope`。它不读取 HEAD，不获得授权，不验证物理存储世代，也不证明这个对象由当前权威引用。

它不验证引用的传递闭包、相邻节点边界、完整数据树或请求树，不验证 retained result 的 SQL 编码及与请求索引的关系，不打开或校验 native SQLite，也不证明本地 publication、持久化、pin 存活或 generation promotion 安全。上述工作继续由现有对应层执行；本层没有提供闭包游标、dry-run 维护入口或将校验结果升级为维护授权。

## 验证范围

[新增单元测试](../../crates/scap-object/src/object_frame_tests.rs) 检查借用阶段没有物化 raw Vec、精确原始切片身份、非规范化 JSON 的字节与哈希保留、owned 返回值脱离输入后的生命期、完整 Scope、嵌入 raw 字段、类型和本对象结构。现有 [format 测试](../../crates/scap-object/src/format_tests.rs) 继续通过公开编码与解码路径检查全部边界、外层 `Limit` 优先级和其余 `Corrupt` 结果。覆盖策略将新生产模块正常纳入第一方单元分母，不豁免代码或用集成 profile 补足。

实际执行结果由绑定源码的验证记录报告；此设计说明本身不代表 unit、native 或真实对象存储验收已经通过。
