"""Run the actual shell boundaries. No compiler or Docker execution is implied."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import bootstrap
from test_bootstrap import checkout

HERE = Path(__file__).parent.resolve()


class EntrypointTests(unittest.TestCase):
    def layout(self, root):
        repo, native = checkout(root)
        prefix = root / 'prefix'
        for sub in ('cargo', 'offline-cargo'):
            (prefix / sub).mkdir(parents=True)
            (prefix / sub / 'config.toml').write_text('[source.vendored]\ndirectory="/fixture-only"\n')
        record = {
            'status': 'environment_ready', 'prefix': str(prefix),
            'dependencies': bootstrap.dependency_inputs(repo),
            'vendor_config_sha256': bootstrap.sha(prefix / 'cargo/config.toml'),
            'scope': 'Metadata fixture, not an installed toolchain',
        }
        (prefix / 'READY.json').write_text(json.dumps(record))
        env = dict(os.environ, SCAP_REPO=str(repo), SCAP_ENV_PREFIX=str(prefix),
                   SCAP_BOOTSTRAP=str(HERE / 'bootstrap.py'), TMPDIR=str(root),
                   LLVM_PROFILE_FILE='wrong.profraw', RUSTFLAGS='-C instrument-coverage',
                   RUSTUP_DIST_SERVER='http://untrusted.invalid', RUSTC_WRAPPER='/wrong/wrapper')
        return repo, prefix, env

    def test_real_entry_check_uses_unused_evidence_path_and_runs_command_offline(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, prefix, env = self.layout(Path(tmp))
            code = ('import json,os; print(json.dumps({"cwd":os.getcwd(),'
                    '"home":os.environ["CARGO_HOME"],"offline":os.environ["CARGO_NET_OFFLINE"],'
                    '"flags":os.environ.get("RUSTFLAGS"),"profile":os.environ.get("LLVM_PROFILE_FILE"),'
                    '"mirror":os.environ.get("RUSTUP_DIST_SERVER"),"wrapper":os.environ.get("RUSTC_WRAPPER")}))')
            run = subprocess.run(['bash', str(HERE / 'enter.sh'), sys.executable, '-c', code],
                                 env=env, text=True, capture_output=True, timeout=10)
            self.assertEqual(run.returncode, 0, run.stderr)
            report, actual = map(json.loads, run.stdout.splitlines())
            self.assertEqual(report['status'], 'environment_inputs_match')
            self.assertEqual(Path(report['evidence']).name, 'check')
            self.assertTrue((Path(report['evidence']) / 'summary.json').is_file())
            self.assertEqual(actual['cwd'], str(repo))
            self.assertEqual(actual['offline'], 'true')
            self.assertTrue(all(actual[key] is None for key in ('flags', 'profile', 'mirror', 'wrapper')))
            self.assertNotEqual(actual['home'], str(prefix / 'cargo'))
            self.assertEqual((Path(actual['home']) / 'config.toml').read_bytes(),
                             (prefix / 'cargo/config.toml').read_bytes())

    def test_dependency_drift_and_blocked_marker_never_execute_payload(self):
        for condition in ('drift', 'blocked', 'config'):
            with self.subTest(condition=condition), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp); repo, prefix, env = self.layout(root)
                if condition == 'drift': (repo / 'Cargo.lock').write_text('different')
                if condition == 'blocked': (prefix / 'BLOCKED.json').write_text('{}')
                if condition == 'config': (prefix / 'cargo/config.toml').write_text('different')
                marker = root / 'payload-ran'
                run = subprocess.run(['bash', str(HERE / 'enter.sh'), sys.executable, '-c',
                                      f'from pathlib import Path;Path({str(marker)!r}).touch()'],
                                     env=env, text=True, capture_output=True, timeout=10)
                self.assertNotEqual(run.returncode, 0)
                self.assertFalse(marker.exists())
                self.assertEqual(json.loads(run.stdout)['status'], 'blocked')

    def test_payload_exit_status_is_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, _, env = self.layout(Path(tmp))
            run = subprocess.run(['bash', str(HERE / 'enter.sh'), sys.executable, '-c', 'raise SystemExit(23)'],
                                 env=env, text=True, capture_output=True, timeout=10)
            self.assertEqual(run.returncode, 23)

    def test_validator_rejects_inside_relative_existing_and_symlinked_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); repo, _, env = self.layout(root)
            subprocess.run(['git', 'init', '-q', str(repo)], check=True)
            existing = root / 'existing'; existing.mkdir()
            alias = root / 'alias'; alias.symlink_to(repo, target_is_directory=True)
            for path in (repo, repo/'evidence', alias/'evidence', Path('relative'), existing):
                run = subprocess.run(['bash', str(HERE/'validate.sh')], cwd=repo,
                                     env=env | {'SCAP_EVIDENCE': str(path)},
                                     text=True, capture_output=True, timeout=10)
                self.assertNotEqual(run.returncode, 0, str(path))
                self.assertFalse((repo/'evidence').exists())
                self.assertEqual(list(existing.iterdir()), [])

    def test_shell_syntax(self):
        for name in ('enter.sh', 'validate.sh'):
            run = subprocess.run(['bash', '-n', str(HERE/name)], text=True, capture_output=True)
            self.assertEqual(run.returncode, 0, run.stderr)


if __name__ == '__main__':
    unittest.main()
