# 显式快照与新 Scope 恢复：独立有限模型

这是HEAD9设计模型，不含产品代码。协议见[retained-snapshot-restore.md](../../docs/architecture/retained-snapshot-restore.md)，固定域、804正例/48负控和未覆盖项见[PLAN](PLAN.md)。原789正例/38负控的名称与范围全部保留，先前另加15条 refinement 与9条负控；本次再加1条最终授权优先负控；旧运行不能认证更改后的模型。运行结论仅以对应源码指纹的独立manifest为准，本文件不预先声称通过。HEAD8既有单位/actual不能替代这里的新协议验证，这里的模型结果也不能替代后续产品门禁。

| 文件 | 责任 |
| --- | --- |
| `model.py` | 有限持久对象、原ETag候选、四阶段网络、进程退出、源保留根/迁移、两Scope恢复与取消；不导入产品或observer。 |
| `oracle.py` | 独立重放exact GET、条件效果、进程知识、per-root几何、跨Scope数据等价、当前权限与永久proof；只依赖标准库。 |
| `cases.py` | 固定保序交织与每条边界；不使用observer选择或跳过失败分支。 |
| `counterexamples.py` | 48个预先指定rule的协议变体/元数据故障/observer变异，分类在matrix中保留。 |
| `codec_budget.py` | 按实际硬上界计算候选HEAD9各字段JSON尺寸，不冒充未来Rust validator。 |
| `explore.py` | 单进程完整运行，保存全部raw history、源码前后指纹、固定inventory、negative具体拒绝事件和失败。 |
| `test_*.py` | 模型/observer/调度器自测，含隔离执行；不是生产单位profile。 |

模型用真实SHA256和Scope入hash的符号页表现跨Scope重封装，没有模拟SQLite文件页内部格式、压缩、真实S3响应、完整四层树或RSS。它区分source/target/local失败域，`Corrupt`表示受保护依赖失败关闭这一类别；不主张第一条Rust错误或HTTP wire code必然同名。HEAD8的per-generation incident、clone lineage以及native publication仍须产品对应门禁。

控制记录永久、HEAD原ETag不ABA、不可变PUT只Absent、exact GET与conditional DELETE符合已规定的后端合同。source已有一个合法数据根与原请求9001，target始终新sequence/请求空间，不复制原结果身份。目标当前creator/provision检查每个新操作执行；inflight已授权操作不声称可被远程取消。初始source已授予两位目标creator ADMIN+READ，各自Name竞争不会借用对方权限。

普通GC调度抽象继承HEAD6的永久退休及exact条件，不重证LIST分页；cleanup子例另外展示真实whole-batch settle/clear的两次HEAD与Unknown重入。单个有限checkpoint不能证明无限迟到PUT后永久全空。最终source屏障、prepare依赖读取与Name双读的内部竞争只在PLAN中命名的切点展示；不要把804条轨迹解释为任意并发程序的完整状态空间。

本次 completion 屏障在 HEAD1/HEAD2 两次当前授权之后才继续读元数据或比较稳定性；撤权优先 Denied，失败消耗原 prefix。新的负控拒绝把撤权伪装成 Conflict，804/47 旧报告不认证本次804/48。

新增prepare用真实Missing之后的竞争者prepare/capture/release展示跨读竞态；observer独立校验GET顺序与稳定HEAD，不能只信任一个`Corrupt`标签。未来source_revision和重复`(creator,operation)`负控明确注入坏HEAD；合法原ETag协议本身已阻止产生它们。`s1_open`只表示S1读取方拒绝缺失/非null restore_origin这一阶段边界，不认证Rust codec；原S2 target的符号`origin`及全部restore案例仍继续运行。两轮capture/release后实际terminal+payload GC还留下4个永久控制对象，live限额不代表终身metadata有界。

## 复现

只依赖Python3标准库。从仓库根目录执行：

```sh
python3 -m unittest discover -s experiments/object-snapshot-restore-model -p 'test_*.py' -v
python3 experiments/object-snapshot-restore-model/codec_budget.py
python3 experiments/object-snapshot-restore-model/explore.py \
  --out /absolute/path/outside-repository/snapshot-model-attempt-01
```

正式模式要求声明的输入已提交。开发工作树使用`--diagnostic`，仍运行完整804/48，并原样记录dirty source及前后SHA256，不把开发证据冒充clean提交运行。输出目录必须全新；已有目录、超120秒或256MiB evidence均拒绝。即便失败也保留原history和manifest，重新尝试使用新目录。

观察器可以单独复制到空目录，用`python3 -I oracle.py history.json`验证一条轨迹。它不读取模型的summary；三个正控分别检验JSON往返、伪造summary和移除summary。negative必须命中预定rule；任意其他异常都不是通过。

`distinct_head_states/edges`仅统计这次raw histories里实际HEAD条件效果的规范body摘要，不用于剪枝，不等于生产可达状态总量。每个raw GET/PUT/DELETE与Unknown均保留在观察分母，不能以最终Ready或summary替代中途证据。
