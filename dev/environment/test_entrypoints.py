"""Run the actual shell boundaries. No compiler or Docker execution is implied."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

import bootstrap
from test_bootstrap import checkout, fake_node_install

HERE = Path(__file__).parent.resolve()


class EntrypointTests(unittest.TestCase):
    def layout(self, root):
        repo, native = checkout(root)
        prefix = root / 'prefix'
        for sub in ('cargo', 'offline-cargo'):
            (prefix / sub).mkdir(parents=True)
            (prefix / sub / 'config.toml').write_text('[source.vendored]\ndirectory="/fixture-only"\n')
        fake_node_install(None, prefix / 'node')
        record = {
            'status': 'environment_ready', 'prefix': str(prefix),
            'dependencies': bootstrap.dependency_inputs(repo),
            'vendor_config_sha256': bootstrap.sha(prefix / 'cargo/config.toml'),
            'pinned_node': bootstrap.NODE, 'node_archive_sha256': bootstrap.NODE_SHA256,
            'node_executable_sha256': bootstrap.sha(prefix / 'node/bin/node'),
            'npm_cli_sha256': bootstrap.sha(prefix / 'node/lib/node_modules/npm/bin/npm-cli.js'),
            'scope': 'Metadata fixture, not an installed toolchain',
        }
        (prefix / 'READY.json').write_text(json.dumps(record))
        env = dict(os.environ, SCAP_REPO=str(repo), SCAP_ENV_PREFIX=str(prefix),
                   SCAP_BOOTSTRAP=str(HERE / 'bootstrap.py'), TMPDIR=str(root),
                   LLVM_PROFILE_FILE='wrong.profraw', RUSTFLAGS='-C instrument-coverage',
                   RUSTUP_DIST_SERVER='http://untrusted.invalid', RUSTC_WRAPPER='/wrong/wrapper',
                   NODE_OPTIONS='--require=/wrong.js', NODE_PATH='/wrong', NODE_V8_COVERAGE='/old')
        return repo, prefix, env

    def test_real_entry_check_uses_unused_evidence_path_and_runs_command_offline(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, prefix, env = self.layout(Path(tmp))
            code = ('import json,os; print(json.dumps({"cwd":os.getcwd(),'
                    '"home":os.environ["CARGO_HOME"],"offline":os.environ["CARGO_NET_OFFLINE"],'
                    '"flags":os.environ.get("RUSTFLAGS"),"profile":os.environ.get("LLVM_PROFILE_FILE"),'
                    '"mirror":os.environ.get("RUSTUP_DIST_SERVER"),"wrapper":os.environ.get("RUSTC_WRAPPER"),'
                    '"node_options":os.environ.get("NODE_OPTIONS"),"node_path":os.environ.get("NODE_PATH"),'
                    '"node_coverage":os.environ.get("NODE_V8_COVERAGE"),"path":os.environ["PATH"]}))')
            run = subprocess.run(['bash', str(HERE / 'enter.sh'), sys.executable, '-c', code],
                                 env=env, text=True, capture_output=True, timeout=10)
            self.assertEqual(run.returncode, 0, run.stderr)
            report, actual = map(json.loads, run.stdout.splitlines())
            self.assertEqual(report['status'], 'environment_inputs_match')
            self.assertEqual(Path(report['evidence']).name, 'check')
            self.assertTrue((Path(report['evidence']) / 'summary.json').is_file())
            self.assertEqual(actual['cwd'], str(repo))
            self.assertEqual(actual['offline'], 'true')
            self.assertTrue(all(actual[key] is None for key in ('flags', 'profile', 'mirror', 'wrapper',
                                                               'node_options', 'node_path', 'node_coverage')))
            self.assertIn(str(prefix / 'node/bin'), actual['path'].split(os.pathsep))
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
                                     env=env | {'SCAP_EVIDENCE': str(path), 'LC_ALL': 'C',
                                                'SCAP_PYTHON': '/missing/scap-python',
                                                'SCAP_WEED': '/missing/scap-weed'},
                                     text=True, capture_output=True, timeout=10)
                self.assertNotEqual(run.returncode, 0, str(path))
                expected = ('must be absolute' if not path.is_absolute() else
                            'File exists' if path == existing else 'must be outside the source checkout')
                self.assertIn(expected, run.stderr)
                self.assertNotIn('/missing/scap-', run.stderr)
                self.assertFalse((repo/'evidence').exists())
                self.assertEqual(list(existing.iterdir()), [])

    def validator_checkout(self, root):
        repo, _, env = self.layout(root)
        (repo / 'scripts').mkdir()
        shutil.copy2(HERE.parents[1] / 'scripts/source_manifest.py', repo / 'scripts/source_manifest.py')
        subprocess.run(['git', 'init', '-q', str(repo)], check=True)
        subprocess.run(['git', 'add', '.'], cwd=repo, check=True)
        subprocess.run(['git', '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                        'commit', '-qm', 'fixture only'], cwd=repo, check=True)
        return repo, env | {'SCAP_EVIDENCE': str(root / 'evidence')}

    def test_validator_records_missing_tool_after_capturing_valid_evidence_boundary(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); repo, env = self.validator_checkout(root)
            run = subprocess.run(['bash', str(HERE / 'validate.sh')], cwd=repo,
                                 env=env | {'SCAP_PYTHON': '/missing/scap-python'},
                                 text=True, capture_output=True, timeout=10)
            self.assertNotEqual(run.returncode, 0)
            self.assertIn('/missing/scap-python', run.stdout)
            self.assertTrue((root / 'evidence/source-before.json').is_file())
            self.assertTrue((root / 'evidence/source-verify.log').is_file())
            self.assertNotEqual(json.loads((root / 'evidence/completion.json').read_text())['exit_code'], 0)
            self.assertFalse((root / 'evidence/format.log').exists())

    def test_validator_rejects_wrong_node_before_compilation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); repo, env = self.validator_checkout(root)
            tools = root / 'version-fixtures'; tools.mkdir()
            # Explicit version-output fixtures, not actual toolchain acceptance.
            for name, output in [('python', '7.10.6'), ('weed', '4.51 153ab668c99731a6d29492bf6c61d0b4fa701101'),
                                 ('node', 'v99.0.0')]:
                path = tools / name; path.write_text('#!/bin/sh\nprintf "%s\\n" "' + output + '"\n'); path.chmod(0o755)
            run = subprocess.run(['bash', str(HERE / 'validate.sh')], cwd=repo,
                                 env=env | {'SCAP_PYTHON': str(tools / 'python'), 'SCAP_WEED': str(tools / 'weed'),
                                            'PATH': str(tools) + os.pathsep + env['PATH']},
                                 text=True, capture_output=True, timeout=10)
            self.assertNotEqual(run.returncode, 0)
            self.assertEqual((root / 'evidence/node-version.log').read_text(), 'v99.0.0\n')
            self.assertNotEqual(json.loads((root / 'evidence/completion.json').read_text())['exit_code'], 0)
            self.assertFalse((root / 'evidence/format.log').exists())

    def test_shell_syntax(self):
        for name in ('enter.sh', 'validate.sh'):
            run = subprocess.run(['bash', '-n', str(HERE/name)], text=True, capture_output=True)
            self.assertEqual(run.returncode, 0, run.stderr)

    def test_concurrent_validators_own_distinct_build_outputs_and_clear_instrumentation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); repo, env = self.validator_checkout(root)
            tools = root / 'version-fixtures'; tools.mkdir()
            for name, output in [('python', '7.10.6'),
                                 ('weed', '4.51 153ab668c99731a6d29492bf6c61d0b4fa701101'),
                                 ('node', 'v22.16.0'), ('npm', '10.9.2')]:
                path = tools / name
                path.write_text('#!/bin/sh\nprintf "%s\\n" "' + output + '"\n')
                path.chmod(0o755)
            # Stop at the real shell's first compiler call, recording its actual
            # environment. This fixture never pretends to compile or test Rust.
            cargo = tools / 'cargo'
            cargo.write_text('#!' + sys.executable + '\n'
                             'import json,os,pathlib\n'
                             'names=("CARGO_TARGET_DIR","LLVM_PROFILE_FILE","RUSTFLAGS",'
                             '"CARGO_ENCODED_RUSTFLAGS","RUSTC","RUSTC_WRAPPER","RUSTC_WORKSPACE_WRAPPER",'
                             '"NODE_OPTIONS","NODE_PATH","NODE_V8_COVERAGE")\n'
                             'pathlib.Path(os.environ["SCAP_EVIDENCE"],"compiler-environment.json")'
                             '.write_text(json.dumps({n:os.environ.get(n) for n in names}))\n'
                             'raise SystemExit(17)\n')
            cargo.chmod(0o755)
            processes = []
            for index in range(2):
                evidence = root / f'evidence-{index}'
                actual = env | {'SCAP_EVIDENCE': str(evidence),
                                'SCAP_PYTHON': str(tools / 'python'), 'SCAP_WEED': str(tools / 'weed'),
                                'PATH': str(tools) + os.pathsep + env['PATH'],
                                'CARGO_TARGET_DIR': str(root / 'shared-target'),
                                'RUSTC': '/wrong/rustc',
                                'CARGO_ENCODED_RUSTFLAGS': '-C\x1finstrument-coverage',
                                'RUSTC_WORKSPACE_WRAPPER': '/wrong/wrapper'}
                processes.append((evidence, subprocess.Popen(['bash', str(HERE / 'validate.sh')],
                                  cwd=repo, env=actual, text=True,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE)))
            targets = []
            for evidence, process in processes:
                stdout, stderr = process.communicate(timeout=15)
                self.assertEqual(process.returncode, 17, stdout + stderr)
                record = json.loads((evidence / 'compiler-environment.json').read_text())
                target = Path(record.pop('CARGO_TARGET_DIR'))
                self.assertEqual(target.name, 'stable-unit')
                self.assertTrue(target.parent.is_dir())
                self.assertEqual(target.parent.parent, repo / 'target')
                self.assertEqual((evidence / 'target-directory.txt').read_text().strip(), str(target.parent))
                self.assertTrue(all(value is None for value in record.values()))
                self.assertEqual(json.loads((evidence / 'completion.json').read_text())['exit_code'], 17)
                targets.append(target)
            self.assertNotEqual(targets[0], targets[1])
            self.assertFalse((root / 'shared-target').exists())


if __name__ == '__main__':
    unittest.main()
