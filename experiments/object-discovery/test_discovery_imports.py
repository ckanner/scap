"""Service modules and cached generic names must not redirect this fixture."""
import json
from pathlib import Path
import subprocess
import sys
import unittest


class LocalModuleIdentity(unittest.TestCase):
    def test_service_first_path_and_cached_conflicts_leave_both_test_orders_valid(self):
        directory = Path(__file__).resolve().parent
        service = directory.parent / "object-service"
        code = r'''
import json,sys,types,unittest
from pathlib import Path
directory,service=map(Path,sys.argv[1:])
sys.path[:0]=[str(service),str(directory)]
for name in ('discovery_contract','discovery_proxy','discovery_oracle','discovery_spec','discovery_build','discovery_build_audit'):
    decoy=types.ModuleType(name);decoy.wrong_service_identity=True;sys.modules[name]=decoy
from deployment_recovery_imports import local
controller=local('discovery_contract');oracle=local('discovery_oracle');proxy=local('discovery_proxy')
assert controller.Proxy is proxy.Proxy and controller.sha is proxy.sha
assert oracle.Metadata is local('discovery_metadata_audit').Metadata
for module in (controller,oracle,proxy,local('discovery_spec'),local('discovery_build')):
    assert Path(module.__file__).parent==directory
assert sys.modules['discovery_oracle'].wrong_service_identity
first=local('test_discovery_oracle');second=local('test_discovery_build')
cases=[first.OriginalInputsAndAuthentication('test_original_mac_is_recomputed_for_method_path_body_condition_and_headers'),
       first.StableMetadataControls('test_absent_binding_allows_distinct_error_ids_but_never_a_presence_change'),
       second.BuildIdentityControls('test_full_requires_original_source_compiler_raw_cargo_native_link_and_binary')]
assert unittest.TextTestRunner().run(unittest.TestSuite(cases)).wasSuccessful()
cases=[second.BuildIdentityControls('test_full_requires_original_source_compiler_raw_cargo_native_link_and_binary'),
       first.StableMetadataControls('test_absent_binding_allows_distinct_error_ids_but_never_a_presence_change'),
       first.OriginalInputsAndAuthentication('test_original_mac_is_recomputed_for_method_path_body_condition_and_headers')]
assert unittest.TextTestRunner().run(unittest.TestSuite(cases)).wasSuccessful()
print(json.dumps({'local_modules':True,'service_cache_preserved':True,'orders':2,'selected_behavior_tests':6}))
'''
        completed = subprocess.run([sys.executable, "-c", code, str(directory), str(service)],
                                   capture_output=True, text=True, timeout=20)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(json.loads(completed.stdout), {"local_modules": True, "service_cache_preserved": True,
                                                       "orders": 2, "selected_behavior_tests": 6})
