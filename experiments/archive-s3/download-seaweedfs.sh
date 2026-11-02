#!/usr/bin/env bash
set -euo pipefail
scap_archive_tools="${1:?usage: download-seaweedfs.sh DESTINATION}"
mkdir -p "$scap_archive_tools"
cd "$scap_archive_tools"
curl --fail --location --silent --show-error \
  https://github.com/seaweedfs/seaweedfs/releases/download/4.51/linux_amd64.tar.gz \
  --output seaweedfs-4.51-linux-amd64.tar.gz
printf '%s\n' 'c03be37416a8ee672c77766e20b22a4e1430744c3af2668599a4b6eeaec14cee  seaweedfs-4.51-linux-amd64.tar.gz' | sha256sum --check --strict
tar -xzf seaweedfs-4.51-linux-amd64.tar.gz weed
./weed version
