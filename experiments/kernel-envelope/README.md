# Kernel resource envelope：真实内核合同

固定 **14 个实际场景**：正式 release `scapd --check-config` 的 1 个准入成功和 9 个
拒绝，以及独立压力程序的 OOM、CPU throttle、任务数拒绝和 ENOSPC 后释放/重用。
完整冻结输入、判据、证据链和信任边界见 [PLAN.md](PLAN.md)。生产设计见
[内核资源准入](../../docs/architecture/kernel-resource-envelope.md)。

要求真实 Linux cgroup v2、systemd、无交互 sudo 和可读的正式 release/native 构建
产物。固定 CI 运行器为 GitHub `ubuntu-24.04`。当前夹具必须与同一源码 commit 的
正式构建匹配；不要用旧构建运行新 Rust/SDK 候选。路径限定为绝对路径且无空白、
shell 分隔字符，以便原 `ExecStart` 可以无歧义绑定到完整 argv。

```sh
python3 -B -m unittest discover -s experiments/kernel-envelope -p test_contract.py
python3 -B experiments/kernel-envelope/run.py \
  --server /absolute/target/release/scapd \
  --build-record /absolute/build/build.json \
  --evidence /absolute/new-kernel-evidence
python3 -B experiments/kernel-envelope/oracle.py /absolute/new-kernel-evidence
python3 -B experiments/kernel-envelope/controls.py /absolute/new-kernel-evidence \
  --output /absolute/new-kernel-controls
```

所有输出目录必须全新；控制输出必须位于 evidence 之外。runner 自动保存完整
fixture 源归档、正式 build receipt、每例原 config、pre-exec 内核观察、原 systemd
属性/argv/退出、压力 stdout/stderr 和清理证据，并在结束后调用独立 oracle。
`oracle.py` 仍应作为独立 CI 步骤执行；`controls.py` 要求 24 个指定负控和 2 个正控。

环境缺少 systemd/cgroup v2 时，runner 保留 `run.json` 的 `NOT_RUN` 和已归档夹具，
命令非零退出。正式 build、实际输入或输出不符时保留原失败，不能用单元/合成记录
替代。`test_contract.py` 的合成记录明确标记为 `SYNTHETIC_NOT_ACTUAL`，没有正式
build/native/runtime 证据，完整实际 oracle 必须拒绝。

每例 unit 独立，45 秒运行上限，顺序执行一次。凭据值不归档，私有目录在结束时删除。
stop 后 unit 可能已被 systemd 卸载；清理通过要求原 `is-active` 非活动结果与原 cgroup
消失/空组证据一起成立，不依赖一定还能成功查询 transient unit。

内核记账上限不是瞬时 RSS 精确上限，CFS quota 也不是延迟 SLO。本合同不能证明
AWS Standard、SQL 恢复或租户硬隔离，不能替代持续开环过载的服务合同；主机管理员
仍须维持部署边界，完整限制见计划文档。
