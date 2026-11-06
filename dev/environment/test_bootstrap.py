"""Environment-controller tests, not Rust/toolchain/database acceptance."""
import contextlib
import io
import json
import os
import runpy
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock

import bootstrap as b


def checkout(root):
    repo = root / 'source'; repo.mkdir()
    (repo / 'Cargo.toml').write_text('[workspace]\nmembers=[]\n')
    (repo / 'Cargo.lock').write_text('version=4\n')
    (repo / 'rust-toolchain.toml').write_text('[toolchain]\nchannel="1.90.0"\n')
    (repo / 'experiments/object-network').mkdir(parents=True)
    for name in ('Cargo.toml', 'Cargo.lock'):
        (repo / 'experiments/object-network' / name).write_text('version=4\n')
    native = root / 'libclang'; native.mkdir(); (native / 'libclang.so').write_bytes(b'fixture-only')
    return repo, native


class FakeCommands:
    """Exercise ordering/failure handling without launching installers."""
    def __init__(self, prefix, failure=None, bad_hash=False, drift=None):
        self.prefix, self.failure, self.bad_hash, self.drift = prefix, failure, bad_hash, drift
        self.records = []; self.environments = []
    def download(self, name, url, destination):
        self.records.append({'stage': name, 'url': url})
        if self.failure == name: raise b.Blocked('fixture download failed')
        if name == 'download-rustup-checksum':
            digest = '0' * 64 if self.bad_hash else b.sha(self.prefix / 'downloads/rustup-init')
            destination.write_text(digest + '  rustup-init\n')
        else: destination.write_bytes(b'fixture-only-installer-not-executed')
    def run(self, name, argv, **kwargs):
        self.records.append({'stage': name, 'argv': [str(x) for x in argv]})
        self.environments.append((name, dict(kwargs.get('env', {}))))
        if self.failure == name: raise b.Blocked('fixture stage failure')
        if name == 'install-rustup':
            (self.prefix / 'cargo').mkdir()
        if name == 'vendor-locked-dependencies':
            if self.drift: self.drift.write_text('changed during prepare')
            return '[source.crates-io]\nreplace-with="vendored"\n[source.vendored]\ndirectory="/fixture-only/vendor"\n'
        return ''


class UtilityTests(unittest.TestCase):
    def test_need_and_json_preserve_old_evidence(self):
        b.need(True, 'allowed')
        with self.assertRaises(b.Blocked): b.need(False, 'rejected')
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)/'x.json'; b.exclusive_json(p, {'x': 1})
            self.assertEqual(json.loads(p.read_text()), {'x': 1})
            with self.assertRaises(FileExistsError): b.exclusive_json(p, {})
    def test_inventory_includes_all_lockfiles_ignores_build_outputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, _ = checkout(Path(tmp))
            first = b.dependency_inputs(repo)
            self.assertEqual(len(first), 5)
            (repo/'target').mkdir(); (repo/'target/Cargo.toml').write_text('junk')
            (repo/'README.md').write_text('new docs')
            self.assertEqual(first, b.dependency_inputs(repo))
            (repo/'crates').mkdir(); (repo/'crates/Cargo.toml').write_text('extra')
            self.assertEqual(len(b.dependency_inputs(repo)), 6)
    def test_inventory_rejects_missing_wrong_pin_and_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, _ = checkout(Path(tmp))
            pin = repo/'rust-toolchain.toml'
            pin.write_text('[toolchain]\nchannel="stable"\n')
            with self.assertRaises(b.Blocked): b.dependency_inputs(repo)
            pin.write_text('[toolchain]\nchannel="1.90.0"\n')
            extra = repo/'crates'; extra.mkdir()
            (extra/'Cargo.toml').symlink_to(repo/'Cargo.toml')
            with self.assertRaises(b.Blocked): b.dependency_inputs(repo)
            (extra/'Cargo.toml').unlink(); (repo/'Cargo.lock').unlink()
            with self.assertRaises(b.Blocked): b.dependency_inputs(repo)
    def test_custom_cargo_configuration_cannot_override_offline_sources(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, _ = checkout(Path(tmp))
            (repo/'.cargo').mkdir()
            for name in ('config', 'config.toml'):
                path = repo/'.cargo'/name; path.write_text('[source]')
                with self.assertRaises(b.Blocked): b.dependency_inputs(repo)
                path.unlink()

    def test_isolation_removes_ambient_coverage_and_custom_tool_wrappers(self):
        env = {'PATH': '/usr/bin', 'LLVM_PROFILE_FILE': 'old.profraw', 'RUSTFLAGS': '-C instrument-coverage',
               'CARGO_HOME': '/user/cargo', 'RUSTUP_DIST_SERVER': 'http://untrusted', 'USER_VARIABLE': 'kept'}
        with mock.patch.dict(os.environ, env, clear=True):
            actual = b.isolated_environment(Path('/new'), Path('/clang'))
        self.assertNotIn('LLVM_PROFILE_FILE', actual)
        self.assertNotIn('RUSTFLAGS', actual)
        self.assertNotIn('RUSTUP_DIST_SERVER', actual)
        self.assertEqual(actual['CARGO_HOME'], '/new/cargo')
        self.assertEqual(actual['USER_VARIABLE'], 'kept')
    def test_download_hash_is_checked_before_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)/'binary'; p.write_bytes(b'data'); checksum = Path(tmp)/'sum'
            for content in ('not-hash', '0'*64, 'a'*64+'\nsecond-line'):
                checksum.write_text(content)
                with self.assertRaises(b.Blocked): b.verify_download(p, checksum)
            checksum.write_text(b.sha(p)+'  binary\n')
            self.assertEqual(b.verify_download(p, checksum), b.sha(p))
    def test_weed_extraction_refuses_links_duplicates_and_hash_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            def archive(name, records):
                p = root/name
                with tarfile.open(p, 'w:gz') as f:
                    for kind in records:
                        info = tarfile.TarInfo('weed'); info.size = 4
                        if kind == 'symlink': info.type = tarfile.SYMTYPE; info.linkname='/etc/passwd'
                        f.addfile(info, io.BytesIO(b'data'))
                return p
            source = archive('ok.tar.gz', ['file'])
            with self.assertRaises(b.Blocked): b.extract_weed(source, root/'denied')
            with mock.patch.object(b, 'SEAWEED_SHA256', b.sha(source)):
                b.extract_weed(source, root/'weed')
            self.assertEqual((root/'weed').read_bytes(), b'data')
            self.assertEqual((root/'weed').stat().st_mode & 0o777, 0o755)
            for i, records in enumerate((['symlink'], ['file','file'], [])):
                p = archive(str(i)+'.tar.gz', records)
                with mock.patch.object(b, 'SEAWEED_SHA256', b.sha(p)), self.assertRaises(b.Blocked):
                    b.extract_weed(p, root/f'not-extracted-{i}')


class CommandTests(unittest.TestCase):
    def test_real_subprocess_outputs_and_nonzero_are_retained(self):
        with tempfile.TemporaryDirectory() as tmp:
            command = b.Commands(Path(tmp)/'logs')
            self.assertEqual(command.run('print', ['python3','-c','print("ok")']), 'ok\n')
            with self.assertRaises(b.Blocked): command.run('failure', ['python3','-c','raise SystemExit(7)'])
            self.assertEqual(command.records[-1]['exit_code'], 7)
            with self.assertRaises(b.Blocked): command.run('../unsafe', ['false'])
            with self.assertRaises(FileExistsError): b.Commands(Path(tmp)/'logs')
    def test_launch_errors_and_timeouts_are_not_success(self):
        for error in (FileNotFoundError('missing'), subprocess.TimeoutExpired(['fake'], 1)):
            with tempfile.TemporaryDirectory() as tmp:
                command = b.Commands(Path(tmp)/'logs')
                with mock.patch.object(b.subprocess, 'run', side_effect=error), self.assertRaises(b.Blocked):
                    command.run('launch', ['fake'])
                self.assertEqual(command.records[0]['error_type'], type(error).__name__)
    def test_download_rejects_insecure_scheme_and_preserves_arguments(self):
        with tempfile.TemporaryDirectory() as tmp:
            commands = b.Commands(Path(tmp)/'logs')
            with self.assertRaises(b.Blocked): commands.download('bad','http://example.invalid','dest')
            with mock.patch.object(commands, 'run') as runner:
                commands.download('good','https://example.invalid','dest')
            self.assertIn('--proto',runner.call_args.args[1])
            self.assertIn('=https',runner.call_args.args[1])


class PreparationTests(unittest.TestCase):
    def execute(self, root, *, fail=None, bad_hash=False, drift=False, smoke_fail=False):
        repo, native = checkout(root); prefix = root/'env'
        commands = FakeCommands(prefix, fail, bad_hash, repo/'Cargo.lock' if drift else None)
        with mock.patch.object(b.platform,'system',return_value='Linux'), \
             mock.patch.object(b.platform,'machine',return_value='x86_64'), \
             mock.patch.object(b.shutil,'which',return_value='/usr/bin/present'), \
             mock.patch.object(b,'extract_weed'), \
             mock.patch.object(b,'smoke',side_effect=b.Blocked('smoke failure') if smoke_fail else None,
                               return_value={'scope':'simulated-control-flow-only'}):
            try:
                result = b.prepare(repo, prefix, native, commands)
            except b.Blocked:
                result = None
        return repo, prefix, commands, result
    def test_all_stages_complete_before_ready_and_offline_home_is_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, prefix, commands, result = self.execute(Path(tmp))
            self.assertEqual(result['status'],'environment_ready')
            names = [r['stage'] for r in commands.records]
            self.assertIn('install-stable', names); self.assertIn('install-nightly', names)
            self.assertIn('offline-metadata-1',names)
            self.assertEqual(result['project_validation'],'NOT_RUN')
            self.assertEqual(b.check_ready(repo,prefix)['status'],'environment_ready')
            self.assertNotEqual(result['vendor_config_sha256'],'')
            for name, env in commands.environments:
                if name.startswith('offline-metadata'):
                    self.assertEqual(env['CARGO_HOME'],str(prefix/'offline-cargo'))
                    self.assertEqual(env['CARGO_NET_OFFLINE'],'true')
            self.assertFalse((prefix/'offline-cargo/registry').exists())
            self.assertIn('CARGO_NET_OFFLINE=true',(prefix/'env.sh').read_text())
            vendor = next(r for r in commands.records if r['stage']=='vendor-locked-dependencies')['argv']
            self.assertIn('--locked',vendor); self.assertIn('--sync',vendor)
    def test_every_downstream_failure_never_writes_ready(self):
        stages = ('download-rustup','download-rustup-checksum','install-rustup','install-stable','install-nightly',
                  'install-llvm-cov','create-venv','install-coverage','download-seaweed',
                  'vendor-locked-dependencies','offline-metadata-0','offline-metadata-1','native-compile-probe')
        for stage in stages:
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as tmp:
                _, prefix, commands, result = self.execute(Path(tmp),fail=stage)
                self.assertIsNone(result); self.assertFalse((prefix/'READY.json').exists())
                self.assertFalse((prefix/'env.sh').exists())
                self.assertEqual(json.loads((prefix/'BLOCKED.json').read_text())['status'],'blocked')
    def test_checksum_smoke_and_source_drift_are_mandatory(self):
        for option in ('bad_hash','smoke_fail','drift'):
            with self.subTest(option=option),tempfile.TemporaryDirectory() as tmp:
                _,prefix,commands,result=self.execute(Path(tmp),**{option:True})
                self.assertIsNone(result); self.assertFalse((prefix/'READY.json').exists())
                if option=='bad_hash': self.assertNotIn('install-rustup',[r['stage'] for r in commands.records])
    def test_unsupported_host_and_unsafe_or_existing_prefixes_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);repo,native=checkout(root);commands=FakeCommands(root/'env')
            with mock.patch.object(b.platform,'system',return_value='Darwin'),self.assertRaises(b.Blocked):
                b.prepare(repo,root/'env',native,commands)
            with mock.patch.object(b.platform,'machine',return_value='arm64'),self.assertRaises(b.Blocked):
                b.prepare(repo,root/'env',native,commands)
            with self.assertRaises(b.Blocked): b.prepare(repo,repo/'env',native,commands)
            (root/'env').mkdir()
            with self.assertRaises(b.Blocked): b.prepare(repo,root/'env',native,commands)
            (native/'libclang.so').unlink()
            with self.assertRaises(b.Blocked): b.prepare(repo,root/'new',native,commands)
            (native/'libclang.so').touch()
            with mock.patch.object(b.shutil,'which',return_value=None),self.assertRaises(b.Blocked):
                b.prepare(repo,root/'another',native,commands)
    def test_environment_reuse_detects_dependency_and_configuration_drift(self):
        for mode in ('dependency','config','runtime_config','relocation','not_ready'):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as tmp:
                repo,prefix,_,result=self.execute(Path(tmp))
                if mode=='dependency': (repo/'Cargo.lock').write_text('changed')
                if mode=='config': (prefix/'cargo/config.toml').write_text('changed')
                if mode=='runtime_config': (prefix/'offline-cargo/config.toml').write_text('changed')
                if mode in ('relocation','not_ready'):
                    state=json.loads((prefix/'READY.json').read_text())
                    if mode=='relocation':state['prefix']='/different-prefix'
                    else: state['status']='installing'
                    (prefix/'READY.json').write_text(json.dumps(state))
                with self.assertRaises(b.Blocked): b.check_ready(repo,prefix)
    def test_ready_is_not_published_if_env_script_creation_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); repo, native = checkout(root); prefix = root/'env'
            commands = FakeCommands(prefix)
            original = Path.write_text
            def write(path, *args, **kwargs):
                if path == prefix/'env.sh':
                    raise OSError('injected env.sh failure')
                return original(path, *args, **kwargs)
            with mock.patch.object(b.shutil, 'which', return_value='present'), \
                 mock.patch.object(b, 'extract_weed'), \
                 mock.patch.object(b, 'smoke', return_value={'scope': 'mock only'}), \
                 mock.patch.object(Path, 'write_text', write), self.assertRaises(OSError):
                b.prepare(repo, prefix, native, commands)
            self.assertFalse((prefix/'READY.json').exists())
            self.assertEqual(json.loads((prefix/'BLOCKED.json').read_text())['status'], 'blocked')

    def test_blocked_marker_always_prevents_reuse_of_stale_ready(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, prefix, _, _ = self.execute(Path(tmp))
            (prefix/'BLOCKED.json').write_text('{"status":"blocked"}')
            with self.assertRaisesRegex(b.Blocked, 'blocked preparation'):
                b.check_ready(repo, prefix)

    def test_vendor_config_must_contain_replacement_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);repo,native=checkout(root);prefix=root/'env';commands=FakeCommands(prefix)
            original=commands.run
            def run(name,*args,**kw):
                if name=='vendor-locked-dependencies':return 'unrelated=1\n'
                return original(name,*args,**kw)
            commands.run=run
            with mock.patch.object(b.shutil,'which',return_value='present'),mock.patch.object(b,'extract_weed'),self.assertRaises(b.Blocked):
                b.prepare(repo,prefix,native,commands)
            self.assertFalse((prefix/'READY.json').exists())


class SmokeCommands:
    def __init__(self,prefix,failure=None):self.prefix,self.failure=prefix,failure
    def run(self,name,argv,**kwargs):
        values={'stable-version':'rustc 1.90.0 (fixture)\nhost: x86_64-unknown-linux-gnu',
                'nightly-version':'rustc 1.92.0-nightly (fixture)\nhost: x86_64-unknown-linux-gnu',
                'llvm-cov-version':'cargo-llvm-cov 0.6.21', 'coverage-version':'Coverage.py 7.10.6',
                'libclang-smoke':'Ubuntu clang version 18.0.0',
                'weed-version':'version 4.51 153ab668c99731a6d29492bf6c61d0b4fa701101 linux amd64'}
        if name=='llvm-smoke':
            (self.prefix/'smoke/llvm.json').write_text(json.dumps({'data':[] if self.failure==name else [{}]}))
        return 'wrong-version' if name==self.failure else values.get(name,'')


class SmokeAndCLITests(unittest.TestCase):
    def test_smoke_checks_all_pinned_versions_and_actual_llvm_report(self):
        for stage in (None,'stable-version','nightly-version','llvm-cov-version','coverage-version','libclang-smoke','weed-version','llvm-smoke'):
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as tmp:
                p=Path(tmp);commands=SmokeCommands(p,stage)
                if stage is None:
                    result=b.smoke(p,p,commands,{})
                    self.assertIn('NOT project acceptance',result['scope'])
                else:
                    with self.assertRaises(b.Blocked): b.smoke(p,p,commands,{})
    def test_doctor_collects_failures_and_never_certifies_database(self):
        class Commands:
            records=[]
            def run(self,name,*args,**kw):
                if name in ('host-cxx','network-github'):raise b.Blocked('failed')
                return 'fixture output'
        result=b.doctor(Commands(),Path('/native'))
        self.assertEqual(result['status'],'blocked')
        self.assertEqual(result['project_validation'],'NOT_RUN')
        self.assertEqual(result['network'][1]['status'],'blocked')
        self.assertEqual(result['network'][0]['status'],'reachable')
    def test_cli_doctor_prepare_check_and_exception_reports(self):
        with tempfile.TemporaryDirectory() as tmp,contextlib.redirect_stdout(io.StringIO()):
            root=Path(tmp)
            with mock.patch.object(b,'doctor',return_value={'status':'blocked','project_validation':'NOT_RUN'}):
                self.assertEqual(b.main(['doctor','--evidence',str(root/'doctor')]),1)
            with mock.patch.object(b,'prepare',return_value={'status':'environment_ready'}):
                self.assertEqual(b.main(['prepare','--evidence',str(root/'prepare')]),0)
            with mock.patch.object(b,'check_ready',return_value={}):
                self.assertEqual(b.main(['check','--evidence',str(root/'check')]),0)
            with mock.patch.object(b,'prepare',side_effect=b.Blocked('no network')):
                self.assertEqual(b.main(['prepare','--evidence',str(root/'failed')]),1)
            failure=json.loads((root/'failed/summary.json').read_text())
            self.assertEqual(failure['project_validation'],'NOT_RUN')
            self.assertEqual(failure['error'],'no network')
    def test_python_main_entrypoint_preserves_nonzero_failure(self):
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
            root = Path(tmp)
            with mock.patch.object(sys, 'argv', [b.__file__, 'check', '--prefix', str(root/'missing'),
                                               '--evidence', str(root/'logs')]), self.assertRaises(SystemExit) as exited:
                runpy.run_path(b.__file__, run_name='__main__')
            self.assertEqual(exited.exception.code, 1)
            self.assertEqual(json.loads((root/'logs/summary.json').read_text())['status'], 'blocked')

    def test_actual_cli_missing_checkout_is_nonzero_not_install_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp);script=Path(b.__file__)
            result=subprocess.run([sys.executable,str(script),'check','--repo',str(p),'--prefix',str(p/'missing'),
                                   '--evidence',str(p/'evidence')],capture_output=True,text=True)
            self.assertEqual(result.returncode,1)
            self.assertEqual(json.loads((p/'evidence/summary.json').read_text())['status'],'blocked')


# Import here to keep the selftest executable equally usable by unittest discovery.
import sys
if __name__=='__main__': unittest.main()
