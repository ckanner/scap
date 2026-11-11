# HEAD9 S1 真实 retained snapshot 合同

[PLAN.md](PLAN.md) 是运行前冻结的分母，`spec.py` 给出输入，`run.py` 只装配正式
`scapd`、native worker、公开 Node SDK 和真实签名 SeaweedFS。
没有产品算法替身，也没有 S3 伪造正向 HEAD。一次正常运行仍只输出
`OBSERVED_NOT_AUDITED`，随后由独立 `oracle.py` 审计；原件不能覆盖或改成另一轮结果。

## 实际检查范围

六笔原始 SQL 带随机 BLOB 与 `random()` 返回值，其中前两笔在 native worker 上执行，
后四笔经过真实 Node/HTTP。保留两棵不同当前 Manifest，保留三个原结果窗口，完整 COPY
当前根、两棵 held root 和所有索引/result 后，清除旧物理代；全部 daemon、SDK 与本地缓存
丢弃后，新 worker 从对象存储恢复。两次原 HTTP ACK 丢失始终保持 UNKNOWN，独立后续
inspect 证明 retained/released 状态。Deleted 不能隐式丢点，释放所有点才能 seal。
最终 payload GC 后四份永久 snapshot metadata 必须仍可按原 bytes/ETag 观察。

oracle 的历史点数据期望来自最初保存的 ACK；它独立解码 frame、Merkle 树、原始结果，
把已验证 SQLite image 原样写入私有临时文件，以 `mode=ro&immutable=1` 连接检查完整性及原 BLOB，
随后核实原 bytes 未变且没有 WAL/SHM sidecar。这个方式也能读取原生 WAL-mode 的完整页镜像，
无需修改 header；`:memory:` deserialize 对该模式会试图打开 WAL，不能作为此审计的读入口。
这不是 S2 restore API：本阶段不创建目标 Scope，也不执行快照恢复写入。

## 运行

必须使用包含本目录且干净、已提交的完整源码。正式产品 release receipt 的所有生产输入
必须与该候选相同；可接受同一产品 commit 的后续纯实验提交。两份 build receipt 都要
通过官方构建工具生成，不能用手写 receipt 或 unit 插桩二进制。

```sh
PYTHONDONTWRITEBYTECODE=1 python -m unittest discover \
  -s experiments/object-snapshot-runtime -p 'test_*.py' -v
node --check experiments/object-snapshot-runtime/client.mjs
python experiments/object-snapshot-runtime/run.py \
  --server /absolute/release/scapd \
  --build-record /absolute/service-build/build.json \
  --worker /absolute/release/scap-object-network \
  --seed-build-record /absolute/native-build/build.json \
  --weed /absolute/weed --node /absolute/node \
  --evidence /absolute/new-observation-directory
python experiments/object-snapshot-runtime/oracle.py /absolute/new-observation-directory
python experiments/object-snapshot-runtime/controls.py /absolute/new-observation-directory \
  --out /absolute/new-controls-directory
```

`run.py` 使用四个 Seaweed 子进程、三个正式 daemon incarnations、三个 SDK incarnations、
一个 native 子进程及两个工具版本命令，全部由拥有它们的父进程收割。observer 的
request、connection、handler、原始 payload、真实服务响应与实际交付分别保留。
两个 S3 身份分开：普通 read/write 与显式 GC capability。原始凭据只在私有临时目录；
成功退出后删除该目录，公开证据保存 token/access key 的 hash。

`controls.py` 复制完整原件，十个事先列出的反事实必须命中指定 guard；异常、其他 guard
或意外 PASS 都是负控失败。包括故意省略一个 cold held Manifest GET 后重新闭合其
原交换分母，以验证完整恢复闭包规则本身，而不靠缺一行日志蒙混覆盖这个负控。
原证据文件采用硬链接复制；修改时先断开链接，不改正向原件。
负控开始前保存完整正向文件 inventory，结束后再次比对全部路径、bytes 与 SHA-256；
任何原件变化都使整个负控组失败。

## 边界

本地兼容端点不证明 AWS Standard、S3 Express 的云端故障合同、跨 AZ 耐久性或吞吐 SLO。
运行不是 Rust unit coverage 的来源；本实验不会启用 `LLVM_PROFILE_FILE`、
`-Cinstrument-coverage` 或 `NODE_V8_COVERAGE`。未运行的阶段必须写 `NOT_RUN`。
永久 descriptor/proof 数量仍随历史增长，本实验只证明 payload GC 不误删它们。
