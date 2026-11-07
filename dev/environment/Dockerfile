# Build on an online Linux amd64 host, or with explicit --platform linux/amd64.
# Use BASE_IMAGE=ubuntu@sha256:<verified digest> to additionally pin the OS image.
# ubuntu:24.04 pins the OS release, not individual apt snapshot package versions.
ARG BASE_IMAGE=ubuntu:24.04
FROM ${BASE_IMAGE}
RUN test "$(uname -m)" = x86_64 \
 && apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends \
      build-essential ca-certificates curl git cmake make pkg-config \
      libclang-18-dev python3 python3-venv tar xz-utils \
 && mkdir -p /opt/scap-os-evidence \
 && dpkg-query --show > /opt/scap-os-evidence/packages.txt \
 && rm -rf /var/lib/apt/lists/*
COPY dev/environment/bootstrap.py /usr/local/lib/scap-environment/bootstrap.py
COPY dev/environment/enter.sh /usr/local/bin/scap-enter
COPY dev/environment/validate.sh /usr/local/bin/scap-validate
COPY Cargo.toml Cargo.lock rust-toolchain.toml /tmp/scap-source/
COPY crates /tmp/scap-source/crates
COPY experiments/object-network /tmp/scap-source/experiments/object-network
# prepare installs checksum-pinned Node 22.16.0 plus its bundled npm under
# /opt/scap/node; enter.sh exposes them without relying on host Node packages.
RUN python3 /usr/local/lib/scap-environment/bootstrap.py prepare \
      --repo /tmp/scap-source --prefix /opt/scap --libclang /usr/lib/llvm-18/lib \
      --evidence /opt/scap-build-evidence \
 && chmod 755 /usr/local/bin/scap-enter /usr/local/bin/scap-validate \
 && rm -rf /tmp/scap-source /opt/scap/cargo/registry /opt/scap/cargo/git \
           /opt/scap/rustup/downloads /opt/scap/rustup/tmp /opt/scap/smoke/target /opt/scap/native-probe-target
WORKDIR /work
ENTRYPOINT ["/usr/local/bin/scap-enter"]
CMD ["bash"]
