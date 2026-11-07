"""Synthetic build-evidence controls only; no Rust, service or S3 execution."""
from pathlib import Path
import importlib.util
import unittest


HERE = Path(__file__).resolve().parent
specification = importlib.util.spec_from_file_location(
    "scap_build_evidence_test_support", HERE.parent / "object-network" / "test_build.py")
support = importlib.util.module_from_spec(specification)
specification.loader.exec_module(support)


class ServiceBuildEvidenceTests(support.BuildEvidenceCases, unittest.TestCase):
    builder = support.load_module("scap_service_build_sync_controls", HERE / "build.py")
    entry = "main"
    target_name = "scapd"
    stdout_hash = "cargo.stdout.jsonl_sha256"
    stderr_hash = "cargo.stderr.log_sha256"
    missing_archive = "missing native SQLite build provenance"


if __name__ == "__main__":
    unittest.main()
