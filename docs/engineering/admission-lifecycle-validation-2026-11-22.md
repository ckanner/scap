# 生命周期诊断与相同 seed 对照：验证台账

状态：**实施中，PR 保持 Draft，尚未通过完整验收**。本文件后续只补充当前 PR 的
精确来源、原始失败与派生结论；不将历史结果当作新候选已运行的证明。

[PR #71](https://github.com/ckanner/scap/pull/71) 已先以 `183e925d3e9bcf0a62819bf456e42fd55be05a53`
提交[冻结设计](../architecture/admission-lifecycle-diagnostics.md)，随后开始实现。
基线是已合并 PR #70 的 `20a72da51ff7de96a93a31da669a771ab5ebc12d`。

## 已完成的实现

- 固定五个 intake lane、八个可重叠的驻留 interval、19个含上界微秒桶；固定大小
  trace 附着原 Lease，不增加原工作或字节的 owner。
- HTTP ready 与 worker/encoding 返回分开；group 的可信 consumed 前缀使用共同
  invocation 范围，未消费后缀保留原 enqueue；group attempt 单独聚合。
- 原 quota 退款与 queue pending 移出均先释放业务锁，再做诊断收尾，不改变 native
  先于最后 lease 清理的所有权。原 SQL、身份、deadline、ACK/HEAD/native 屏障不变。
- 默认关闭的独立诊断凭证与 GET 接口；一个65536字节导出额度由 body/frame/clone/
  非空slice保留到最后真实字节 owner 释放。无数据库标识标签，不覆盖 discovery。

实际内存结构为 Registry 9296字节、Trace 152字节、GroupAttempt 40字节、Snapshot
9280字节；所有计数取u64最大值的JSON为29368字节。结构及最坏序列化由独立单元
断言检查，不能把这些固定开销描述为整个进程RSS上限或默认关闭零成本。

## 验证状态

生产代码预检的 Rust stable 全workspace 1019项、fmt与Clippy `-D warnings` 已通过。
这些是冻结前预检，尚未替代最终候选的fresh精确覆盖或真实合同。任何后续受影响
代码变更仍须重新验证，最终来源与数量将单独记录。

| 门槛 | 当前状态 |
| --- | --- |
| 最终候选源码/工具/release身份 | NOT_RUN |
| fresh unit-only四维精确100% | NOT_RUN |
| 生命周期真实TCP/native/S3三场景 | NOT_RUN |
| equal-seed-v1八cell实际/独立oracle/负控 | NOT_RUN |
| AWS Standard/跨AZ/生产SLO/长期工作集 | NOT_RUN |

## 后续判定

保持data intake租户40；本轮目标是确认名额驻留阶段和相同seed起点的有限增长表现。
不通过缩短drain分母、丢弃拒绝或选择有利pair宣称容量提升。完整业务分母、成本、
观察器开销和失败原件将在本文件与派生机器摘要中保留。新的吞吐优化必须在归因后
另立单一机制候选，当前仍不预定某项优化一定有效。
