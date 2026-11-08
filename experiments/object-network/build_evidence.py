"""Capture original build evidence; imported only by build controllers."""
from __future__ import annotations

import hashlib
import io
from pathlib import Path
import tarfile


def digest(path):
    with path.open("rb") as stream:return hashlib.file_digest(stream,"sha256").hexdigest()


def capture(record, evidence, *, value, root, inputs, save_receipt, sync, log_keys):
    """Archive original build witnesses; keep machine paths as retrieval hints.

    The source archive permits later auditing without relying on a permanent
    checkout. It does not claim to archive the executable or native libraries;
    the independent oracle reports those bytes separately when unavailable.
    """
    record, evidence = Path(record), Path(evidence)
    for original, saved, hash_key in (("cargo.stdout.jsonl", "build-cargo.stdout.jsonl", log_keys[0]),
                                      ("cargo.stderr.log", "build-cargo.stderr.log", log_keys[1])):
        raw = (record.parent / original).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == value[hash_key]
        with (evidence / saved).open("xb") as stream:
            stream.write(raw)
            sync(stream)
    manifest = {"schema": 1, "source_commit": value["source_commit"], "inputs": value["inputs"]}
    save_receipt(evidence / "build-source-manifest.json", manifest)
    with (evidence / "build-source.tar").open("xb") as stream:
        with tarfile.open(fileobj=stream, mode="w", format=tarfile.PAX_FORMAT) as archive:
            for name, expected in sorted(value["inputs"].items()):
                raw = (root / name).read_bytes()
                assert hashlib.sha256(raw).hexdigest() == expected, "source changed while archiving"
                info = tarfile.TarInfo(name)
                info.size, info.mode, info.mtime = len(raw), 0o644, 0
                archive.addfile(info, io.BytesIO(raw))
        sync(stream)
    value["archived_evidence"] = {
        "schema": 1,
        "source_manifest": "build-source-manifest.json",
        "source_manifest_sha256": digest(evidence / "build-source-manifest.json"),
        "source_archive": "build-source.tar",
        "source_archive_sha256": digest(evidence / "build-source.tar"),
        "cargo_stdout": "build-cargo.stdout.jsonl",
        "cargo_stderr": "build-cargo.stderr.log",
    }
    assert value["inputs"] == inputs(), "source changed while capturing original build evidence"
    save_receipt(evidence / "build-receipt.json", value)
    return value


