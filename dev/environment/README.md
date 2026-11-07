# 固定开发环境与离线验证入口

本目录是独立开发工具，不改变 S3 权威协议、生产 Rust、容量或依赖锁。**工具控制逻辑、真实 shell 边界与固定 Node/npm 私有安装已测试；完整 Docker 构建、完整 bootstrap prepare 与本入口的全项目验收仍为 NOT_RUN。** 合入本目录不是其它数据库 PR 已通过验收的证明。

## 固定组件

Linux x86_64、Rustup 1.28.2、Rust 1.90.0（rustfmt/clippy）、nightly-2025-09-18（llvm-tools-preview）、cargo-llvm-cov 0.6.21、coverage.py 7.10.6、libclang 18、SeaweedFS 4.51、Node 22.16.0 与随包 npm 10.9.2。S3 后端沿用仓库发布包 SHA-256；安装器从官方 HTTPS 下载并校验官方同源 SHA-256。Node 使用官方 Linux x64 `.tar.xz` 发布包，固定 SHA-256 为 `f4cb75bb036f0d0eddf6b79d9596df1aaab9ddccd6a20bf489be5abe9467e84e`。只写私有新前缀，不改系统 Node、用户 shell 或既有 Rust。

`prepare` 仅在固定版本、校验和、两个 workspace 的完整 vendor、空 Cargo 缓存中的 frozen 依赖解析、原生 SQLite 测试二进制编译链接及 Rust/LLVM、Node/npm 精确版本 smoke 都完成后，才写入 READY。编译测试二进制不等于执行测试，smoke 不等于完整项目验收。

每次使用独占新前缀和证据目录。失败写 BLOCKED，返回非零，不覆盖旧结果。env.sh 必须先写成功才发布 READY；同时存在 BLOCKED 的目录永远拒绝复用。依赖清单、配置或安装路径变化会阻止旧环境继续使用。Node 包先核对固定摘要，再用 Python 3.12 的 tar data filter 在临时目录展开，保留 npm 的目录内 symlink；校验布局后才安装到 `prefix/node`。READY 记录 Node pin、包摘要、实际 node/npm 命令摘要；旧 READY 缺 Node、命令丢失或内容漂移都会拒绝复用。

## 准备与使用

在有网络、Docker 的可信构建机器，在完整 SCAP checkout 内运行：

```bash
docker build --platform linux/amd64 \
  -f dev/environment/Dockerfile -t scap-env:rust-1.90 .
```

默认基础镜像 Ubuntu 24.04 只固定发行版，没有锁 apt snapshot 或 image digest。可通过 `--build-arg BASE_IMAGE=ubuntu@sha256:...` 指定已核验的基础镜像；保存最终 image ID 与构建日志。Apple Silicon 需要显式 linux/amd64 模拟执行。构建过程不修改 DNS、用户 shell 配置或已有 Rust 安装；镜像包含项目源码，不要上传公开 registry 或加入凭据。

已经有 Python 3.12、C/C++、libclang 18 等原生工具的 Linux x86_64，也可使用私有前缀：

```bash
python3 dev/environment/bootstrap.py prepare \
  --repo "$PWD" --prefix "$HOME/.local/share/scap-env-1.90" \
  --libclang /usr/lib/llvm-18/lib --evidence /tmp/scap-prepare-unique
```

准备完成之后，用干净、完整 Git checkout 执行验证：

```bash
mkdir -p "$HOME/scap-evidence"
docker run --rm --platform linux/amd64 --network none \
  --user "$(id -u):$(id -g)" \
  --mount type=bind,src="$PWD",dst=/work \
  --mount type=bind,src="$HOME/scap-evidence",dst=/evidence \
  -e SCAP_EVIDENCE=/evidence/run-001 \
  scap-env:rust-1.90 scap-validate
```

`run-001` 必须不存在且位于源码 checkout 外。symlink 解析后指向源码内也会拒绝。worktree 的外部 Git 数据必须同时可见，不删除身份检查来绕过挂载问题。主仓库/实验的 Cargo.toml、Cargo.lock、rust-toolchain.toml 变化要求重新构建 vendor；本入口不允许仓库 `.cargo/config` 覆盖 source replacement 或 compiler wrapper。

验证先验证并独占创建证据路径、捕获源码身份并安装失败收尾，再检查 Python coverage、SeaweedFS、Node/npm 的固定版本。相对路径、源码内路径、symlink 别名和已有目录必须按路径边界本身拒绝，不能被缺少工具的错误掩盖。之后依次执行格式、严格 Clippy、stable workspace `--lib --bins` 单元、fresh nightly 单元/四维覆盖率、Python 工具、Node codec／SDK 单元及 HTTP、模型、网络／service 夹具自测、独立 release 构建、真实本地 S3 故障、候选存在时的保留结果合同、1 GiB 和真实 service 回归。第一项失败立即停止，退出再次核对源码身份；不合并 PR、不改变 Git refs、不自动重放 SQL。10 GiB 按修改影响范围另行执行，AWS Standard 和生产 SLO 不由本地兼容后端代替。

`enter.sh` 将 `prefix/node/bin` 放在宿主 PATH 之前，并清除旧 Rust／Node 插桩、Node 注入选项和 compiler wrapper，用独立 Cargo home 及只读 vendor 配置运行命令，保留 payload 退出码。可信运维可用 `SCAP_ENV_PREFIX`、`SCAP_BOOTSTRAP` 覆盖工具安装位置，默认仍为镜像固定路径；这些不是数据库用户参数。

## 保存离线环境

只有真实镜像构建成功后，才导出和转移：

```bash
docker image inspect scap-env:rust-1.90 --format '{{.Id}}' > scap-env.image-id.txt
docker image save -o scap-env-linux-amd64.tar scap-env:rust-1.90
sha256sum scap-env-linux-amd64.tar > scap-env-linux-amd64.tar.sha256
# 在目标 Docker 主机核验后导入
sha256sum -c scap-env-linux-amd64.tar.sha256
docker image load -i scap-env-linux-amd64.tar
```

不要把 venv 或绝对安装前缀直接打包宣称可移植。Docker save/load 保持安装路径与 OS 库；本次没有构建或交付任何工具链镜像二进制。

## Node 补全后的实际验证（2026-11-06）

本轮使用 Python 3.12.14／固定 coverage.py 7.10.6：**31 项控制器与真实 shell 边界测试通过，bootstrap.py 280/280 语句、36/36 分支，0 排除**。新增负例覆盖 Node 包摘要／布局／越界 symlink、缺少 Node 的旧 READY、命令内容漂移、固定版本不匹配；路径负例还断言具体边界错误，避免因工具缺失而误报。

已在新的私有前缀实际提取并执行固定 Node v22.16.0 与随包 npm 10.9.2。发布包来自此前下载的官方缓存，包摘要同时匹配固定常量与保存的官方 SHASUMS；本轮重新访问 nodejs.org 的请求因代理 CONNECT 超时失败，原失败保留。真实 npm 离线运行验证内建 test runner、64 位整数/字节视图、UTF-8、AbortController 和 loopback HTTP fetch。这里没有启动完整 prepare、下载或重装 Rust，也没有构建 Docker 镜像。具体摘要与退出码见 [Node 环境验证记录](node-validation-2026-11-06.json)。

现有源码中的完整 validator 已接入 service/SDK 门禁；本轮只验收环境控制与 Node 安装部分，不能把控制器替身或 Node smoke 记为完整数据库验收。

## 并行验收的构建隔离

每次 `validate.sh` 调用在 `target/acceptance.XXXXXXXX` 创建新的专属目录，并把路径保存到证据中的 `target-directory.txt`。stable 单元、coverage 单元、原生 worker release 和 HTTP service release 各有独立子目录；不会复用调用方的 `CARGO_TARGET_DIR`。即使同时验证同一 checkout，也不能替换另一轮构建收据绑定的 worker。目录保留供核对，清理时先确认对应验收已结束。

这是对真实验收中构建身份拒绝的修复：之前两个候选共用 release 输出，较晚构建替换了较早收据对应的二进制，保留结果和 GiB 验收因此在启动前拒绝。原拒绝记录仍保留，不记为数据库通过或数据库失败。实际 shell 回归同时启动两次验证入口，确认输出目录不同、外部插桩与 wrapper 不进入编译，并保留各自退出码；测试中的 compiler 是明确替身，不代替 Rust 验收。

## 初始开发工具诊断（保留历史，2026-11-06）

```bash
python3 -m unittest discover -s dev/environment -p 'test_*.py' -v
bash -n dev/environment/enter.sh
bash -n dev/environment/validate.sh
```

**28 项测试通过，bootstrap.py 248/248 语句、36/36 分支，0 排除。** 本机 Python 3.13.5 / coverage.py 7.13.3 是开发工具诊断环境，不冒充项目固定 coverage.py 7.10.6 或 Rust 验收。控制器测试对安装/下载/native 编译使用明确替身，shell 边界测试实际启动 bash、Python、Git，但用标记清楚的 READY 元数据夹具而非假冒工具链。

提交前修复了原补丁两处缺陷：mktemp 自建证据目录与检查器独占创建相冲突；env.sh 写入失败可能留下 READY。还加入 blocked 标记优先拒绝、依赖/配置漂移、独立 Cargo home、污染变量移除、payload 非零传播、证据目录与 symlink 路径等回归。

初始开发工具评审时的执行容器缺少 Rust/Docker，未重新尝试安装。真实环境准备和数据库回归必须另行执行；本 PR 仅交付可重复的准备/验证代码与已执行的控制器测试。

官方接口参考：
- Rustup: https://rust-lang.github.io/rustup/installation/other.html
- Cargo vendor: https://doc.rust-lang.org/cargo/commands/cargo-vendor.html
- Docker image save: https://docs.docker.com/reference/cli/docker/image/save/
- Node 22.16.0 官方摘要: https://nodejs.org/dist/v22.16.0/SHASUMS256.txt
