# 对象权威 N0：协议模型与独立历史判定

这里是 [N0 协议规格](../../docs/engineering/object-authority-n0.md)的可执行研究模型。它建模可信候选构造、按 ETag 的单 HEAD 发布及故障观察，不连接 AWS，不执行 SQLite，不构成可部署后端。正式产品不能依赖本目录；将来复用任何产品逻辑必须进入生产源码和原精确覆盖率门禁。

## 模型边界

- 单个不可复用 authority scope、有限参与者、合成整数业务值和有界结果 token；业务变化是抽象状态，不是 SQL/WAL。
- principal 和 fingerprint 是可信准入交给模型的身份/业务符号。模型检查绑定、冲突和当前授权，不实现真实凭据验证或 SQL/参数规范化；这些入口不能由不可信客户端自报，在 N1/N2 另行实现和测试。
- HEAD GET 与条件写是显式假设。存储只比较 ETag；业务权限、owner、请求世代及前序数据检查属于可信协议。
- stage、逐个依赖上传、闭包验证、CAS 发出/执行/响应、本地发布与业务响应分开，可以观察响应丢失及全部本地状态丢失。
- 默认探索窗口为 2，保留最近 2 个完整 closed 窗口和 current；对象总数 96、计数器 255、未决尝试 8 的上限用于有限实验，不是线上容量。
- Close 仅对满窗口由可信协调器提出；旧 epoch 永久不再接受。结果查不到时严格区分 unknown、closed、retired 和 cancelled。
- 没有物理 GC，旧对象和未发布残留仍占预算。计数器/对象/请求预算不足就背压，不用静默淘汰或隐式成功解除限额。

## 运行

使用 Python 3.11 或更新版本，仅依赖标准库：

```sh
python3 -m unittest discover -s experiments/object-authority-model -p 'test_*.py' -v

python3 experiments/object-authority-model/explore.py \
  --output /absolute/new-object-model-evidence
```

每次使用新目录，不能覆盖原尝试。原始历史和 summary 应在进程退出后再复制或打包；失败历史保留。具体成功场景、状态/转换数、负对照数及源码 SHA 以该次输出为准，不把模板中的目标算作已执行。

2026-11-05 的本地执行通过 89 项单元、664 条合法历史（640 预定竞态与 24 定向场景）和 30 条预期拒绝的人工反例，见[执行证据](../../docs/evidence/object-n0-local-2026-11-05.json)及[枚举范围说明](../../docs/engineering/object-authority-n0.md)。这些结果不关闭整个 N0，也不验证真实 S3/SQLite。

## 独立判定

`model.py` 是被测离散协议，`oracle.py` 只读取原始事件，不导入被测模型或调用候选构造函数。`explore.py` 枚举有限交错并把轨迹交给独立判定器。`test_oracle.py` 构造明确错误的轨迹，验证判定器确实拒绝提前成功、旧写者覆盖、结果分离、缺依赖、错误取消、旧差分换 ETag、提前退休等错误。

必须报告实际枚举的范围与完整分母。多个预定场景和有限排列通过，不等于遍历了所有状态或证明了任意执行。模型中的 object durability、令牌比较和可信调用者都是显式假设，不能用模型通过代替真实 S3、SQL gate、多进程和生产故障实验。

机器可读语义与 profile 见 [object-authority-model.json](../../contracts/object-authority-model.json)。正式字节格式、真实预算、调度活性、目录、多库、pin/GC/PITR 和成本仍按 N0–N4 继续验证；本目录不继承旧 Raft 单元或故障结果作为新协议证据。
