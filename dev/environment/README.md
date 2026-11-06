# 固定开发环境与离线验证入口

本目录是独立开发工具，不改变 S3 权威协议、生产 Rust、容量或依赖锁。**工具控制逻辑和真实 shell 边界已测试；真实 Docker 构建、工具链安装及原生数据库验收仍为 NOT_RUN。** 合入本目录不是其它数据库 PR 已通过验收的证明。

## 固定组件

Linux x86_64、Rustup 1.28.2、Rust 1.90.0（rustfmt/clippy）、nightly-2025-09-18（llvm-tools-preview）、cargo-llvm-cov 0.6.21、coverage.py 7.10.6、libclang 18、SeaweedFS 4.51。S3 后端沿用仓库发布包 SHA-256；安装器从官方 HTTPS 下载并校验官方同源 SHA-256。没有给当前主机安装任何新软件。

`prepare` 仅在固定版本、校验和、两个 workspace 的完整 vendor、空 Cargo 缓存中的 frozen 依赖解析、原生 SQLite 测试二进制编译链接及 Rust/LLVM smoke 都完成后，才写入 READY。编译测试二进制不等于执行测试，smoke 不等于完整项目验收。

每次使用独占新前缀和证据目录。失败写 BLOCKED，返回非零，不覆盖旧结果。env.sh 必须先写成功才发布 READY；同时存在 BLOCKED 的目录永远拒绝复用。依赖清单、配置或安装路径变化会阻止旧环境继续使用。

## 准备与使用

在有网络、Docker 的可信构建机器，在完整 SCAP checkout 内运行：

```bash
docker build --platform linux/amd64 \
  -f dev/environment/Dockerfile -t scap-env:rust-1.90 .
```

默认基础镜像 Ubuntu 24.04 只固定发行版，没有锁 apt snapshot 或 image digest。可通过 `--build-arg BASE_IMAGE=ubuntu@sha256:...` 指定已核验的基础镜像；保存最终 image ID 与构建日志。Apple Silicon 需要显式 linux/amd64 模拟执行。构建过程不修改 DNS、用户 shell 配置或已有 Rust 安装；镜像包含项目源码，不要上传公开 registry 或加入凭据。

已经有 C/C++、libclang 18 等原生工具的 Linux x86_64，也可使用私有前缀：

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

验证顺序为格式、严格 Clippy、fresh Rust 单元/四维覆盖率、工具测试、模型、独立 release 构建、真实本地 S3 故障、候选存在时的保留结果合同、1 GiB 回归。第一项失败立即停止，退出再次核对源码身份；不合并 PR、不改变 Git refs、不自动重放 SQL。10 GiB 按修改影响范围另行执行，AWS Standard 和生产 SLO 不由本地兼容后端代替。

`enter.sh` 清除旧插桩和 compiler wrapper，用独立 Cargo home 及只读 vendor 配置运行命令，保留 payload 退出码。可信运维可用 `SCAP_ENV_PREFIX`、`SCAP_BOOTSTRAP` 覆盖工具安装位置，默认仍为镜像固定路径；这些不是数据库用户参数。

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

## 本轮验证边界（2026-11-06）

```bash
python3 -m unittest discover -s dev/environment -p 'test_*.py' -v
bash -n dev/environment/enter.sh
bash -n dev/environment/validate.sh
```

**28 项测试通过，bootstrap.py 248/248 语句、36/36 分支，0 排除。** 本机 Python 3.13.5 / coverage.py 7.13.3 是开发工具诊断环境，不冒充项目固定 coverage.py 7.10.6 或 Rust 验收。控制器测试对安装/下载/native 编译使用明确替身，shell 边界测试实际启动 bash、Python、Git，但用标记清楚的 READY 元数据夹具而非假冒工具链。

提交前修复了原补丁两处缺陷：mktemp 自建证据目录与检查器独占创建相冲突；env.sh 写入失败可能留下 READY。还加入 blocked 标记优先拒绝、依赖/配置漂移、独立 Cargo home、污染变量移除、payload 非零传播、证据目录与 symlink 路径等回归。

当前执行容器缺少 Rust/Docker，未重新尝试安装。真实环境准备和数据库回归必须另行执行；本 PR 仅交付可重复的准备/验证代码与已执行的控制器测试。

官方接口参考：
- Rustup: https://rust-lang.github.io/rustup/installation/other.html
- Cargo vendor: https://doc.rust-lang.org/cargo/commands/cargo-vendor.html
- Docker image save: https://docs.docker.com/reference/cli/docker/image/save/
