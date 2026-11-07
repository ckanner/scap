# 名称目录 HTTP 入口

普通数据库操作继续使用 `POST /v1`。名称目录使用独立的 `POST /v1/catalogue`，请求必须带 bearer 和 `x-scap-admission: catalogue`；两者都使用 `content-type: application/json`。目录请求没有外层 `scope`、`tenant`、`principal` 或 `provision` 字段：部署、租户及当前主体由服务的凭据配置决定。

## 独立有界准入

配置缺省不启用目录。启用时在服务 JSON 中明确填写：

```json
{
  "catalogue": {
    "workers": 2,
    "queued_total": 32,
    "queued_per_tenant": 16,
    "queued_per_name": 4,
    "intake": 8,
    "max_body_bytes": 65536,
    "timeout_ms": 10000
  }
}
```

这是顶层配置的新增字段示例；完整部署仍须提供既有 listener、S3、cache、admission 和 credentials 配置。`workers` 允许 1–32，`queued_total` 允许 1–65536；必须满足 `1 <= queued_per_name <= queued_per_tenant <= queued_total`。`intake` 允许 1–4096，正文上限为 64 KiB，绝对请求预算允许 1–86400000 ms。

所有目录线程共享一个全局队列，所以全局上限不会随 worker 数量相乘。队列在同一互斥区间检查全局、租户和精确名称预算，并按租户和名称轮转。按 create operation 查证的请求在首次对象读取前不知道名称；它的排队成本保守计入这个租户每个可能名称的预算，因此改变 operation ID 不能绕过同名上限。运行中的请求另受 worker 数量限制。

目录的 intake 许可会随响应正文及其已发出字节保留，直到最后持有者释放；上传、排队、对象调用和等候响应使用同一原始 deadline。目录请求、结果和线程不借用普通 SQL、control 或 recovery 的配额。饱和返回 `BACKPRESSURE`；已经提交后失去响应返回 `UNKNOWN`，不会暗示修改已回滚。

## 严格原意图

所有 u64 字段都是规范十进制字符串；可空 revision 必须显式填写 `null` 或非零十进制字符串。名称为 1–128 个 UTF-8 字节，大小写和 Unicode 字节精确匹配，拒绝 Unicode Cc 控制字符，不 trim 或归一化。未知字段、重复 JSON 字段、JSON number 形式的身份和遗漏的 nullable 字段均被拒绝。

准备创建请求：

```json
{
  "version": 1,
  "operation": "prepare_create",
  "name": "orders",
  "create_operation": "1001",
  "expected_name_revision": null,
  "options": { "quota": { "mode": "default" } }
}
```

quota 的三态分别为 `{"mode":"default"}`、`{"mode":"unlimited"}`、`{"mode":"limited","max_bytes":"10737418240"}`。准备成功只表示原创建 descriptor 已持久；它不代表名称已经 Reserved 或数据库已经 Ready。有效初始 quota 和 retention 随 descriptor 持久并返回，重入不会重新解释后来变更的默认值。

准备返回的 `creation` 是完整公开引用：`creator`、原创建 `operation`、`name`、完整 `scope` 和 `expected_name_revision`。后续请求必须保留整个引用：

| operation | 原意图字段 |
| --- | --- |
| `prepare_create` | `name`、`create_operation`、`expected_name_revision`、`options` |
| `resume_create` | `creation` |
| `inspect_create_operation` | `create_operation` |
| `resolve_name` | `name` |
| `abort_create` | `creation`、`control_operation`、`expected_name_revision`、`nonce` |
| `delete_name` | `creation`、`control_operation`、`expected_name_revision`、`expected_head_revision`、`nonce` |

创建、续作、取消和原创建操作查证要求当前服务凭据仍有 provision，且调用者是原 creator。resolve 需要当前 HEAD 的 READ。正常删除要求当前 HEAD 的 ADMIN，可以由不同于 creator 的主体执行，也不要求 provision；ADMIN-only 调用者使用已经知道的完整 Creation 和预期 revisions，服务不会把 ADMIN 自动等同于 READ 或帮它绕过发现权限。

创建进度完整返回 `not_reserved`、`reserved`、`provisioning`、`bound`、`ready`、`aborting`、`aborted`、`deleting`、`deleted`、`name_conflict`、`identity_conflict`。取消另有 `cannot_abort_bound`，删除另有 `not_deleted`。中间状态不能当作完成。名字已经重用时，原创建操作的 `binding_revision` 是 `null`，不会把新绑定 revision 冒充为旧操作的可用条件。

响应继续使用 `{ "ok": true, "value": ... }` 或 `{ "ok": false, "error": ... }`。错误分别保留 `INVALID`、`DENIED`、`NOT_FOUND`、`CONFLICT`、`IDENTITY_CONFLICT`、`CORRUPT`、`LIMIT`、`UNKNOWN`。resolve 的公开 HEAD 使用既有 DatabaseStatus 投影；目录内的来源、删除证明、ETag 和对象 key 不会出现在公开状态，也不存在允许客户端写这些字段的 HTTP 入口。普通 lifecycle 操作不能把库设置为内部 `provisioning`。

客户端需要在发送前保存完整原意图。`UNKNOWN` 后只显式查证或重入相同意图；更换 control operation、Scope、revision、nonce 或名称属于新的用户决定。固定 SQL 请求始终绑定原 Scope，名称重用不会使旧 SQL 自动指向新库。

此接口只提供精确名称及原创建操作查证。全目录枚举、分页完整性、冷启动完整 inventory 和物理 GC 仍有各自的实现与验收合同。
