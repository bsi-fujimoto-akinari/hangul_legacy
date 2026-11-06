#!/usr/bin/env python3
"""Manual inventory only. Metadata never establishes known-good rollback.

The repository is public: GitHub guard GETs deliberately use no credential and
need no Actions token permission. Permission/rate failures stop before auth.
Run `self-test` for offline fixtures; it never reads credentials or the network.
"""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import urllib.request

REPO = 'bsi-fujimoto-akinari/hangul_legacy'
SCRIPT = '1p_e1jKICTZXHpCrQ7rwU9HilloZdkFBpHry_lCq5YgXpaiU4FNEQlDa-'
DEPLOYMENT = 'AKfycbxmJnIPTKJY5beUVAU5d0RyKb0Nj-YarY8EkdyczgXHpJKVw4-0kdjv6cYEUXEDtw5D'
OWNER_URL = 'https://script.google.com/macros/s/' + DEPLOYMENT + '/exec'
INVENTORY = 'READ_ONLY_INVENTORY'
MAX_BYTES = 1048576
STAGES = frozenset({
    'IMMUTABLE_MAIN_OR_AUDIT_GUARD', 'TARGET_OR_PINNED_CLI_VERSION',
    'CREDENTIAL_PRESENCE_OR_JSON_SCHEMA', 'CREDENTIAL_FILE_LIFECYCLE',
    'LIST_DEPLOYMENTS_COMMAND', 'LIST_VERSIONS_COMMAND',
    'CLI_RESPONSE_JSON_OR_BOUNDS', 'METADATA_NORMALIZATION',
    'SAFE_OUTPUT_FAILURE', 'INVOCATION_MODE',
})
CODES = frozenset({'OPERATION_FAILED', 'TIMEOUT', 'COMMAND_FAILED',
                   'INVALID_JSON', 'INVALID_VALUE', 'OUTPUT_BOUND'})


class Diagnostic(Exception):
    def __init__(self, stage, code):
        # Reject arbitrary exception attributes before they reach output.
        self.stage = stage if stage in STAGES else 'INVOCATION_MODE'
        self.code = code if code in CODES else 'OPERATION_FAILED'
        super().__init__()


def checked(stage, operation):
    try:
        return operation()
    except Diagnostic:
        raise
    except subprocess.TimeoutExpired:
        raise Diagnostic(stage, 'TIMEOUT') from None
    except subprocess.CalledProcessError:
        raise Diagnostic(stage, 'COMMAND_FAILED') from None
    except json.JSONDecodeError:
        raise Diagnostic(stage, 'INVALID_JSON') from None
    except ValueError:
        raise Diagnostic(stage, 'INVALID_VALUE') from None
    except Exception:
        raise Diagnostic(stage, 'OPERATION_FAILED') from None


def get_json(path):
    # Fixed GitHub origin, no redirects, credentials, user URLs or retries.
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            return None
    req = urllib.request.Request('https://api.github.com/repos/' + REPO + path,
                                 headers={'Accept': 'application/vnd.github+json'})
    with urllib.request.build_opener(NoRedirect).open(req, timeout=20) as response:
        raw = response.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError('BOUND')
    return json.loads(raw)


def guard():
    sha = os.environ.get('GITHUB_SHA', '')
    if (os.environ.get('GITHUB_REPOSITORY') != REPO
            or os.environ.get('GITHUB_EVENT_NAME') != 'workflow_dispatch'
            or os.environ.get('GITHUB_REF') != 'refs/heads/main'
            or os.environ.get('GITHUB_RUN_ATTEMPT') != '1'
            or not re.fullmatch('[0-9a-f]{40}', sha)):
        raise ValueError('CONTEXT')
    if json.loads(Path('.clasp.json').read_text())['scriptId'] != SCRIPT:
        raise ValueError('SCRIPT')
    head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
    if head != sha or get_json('/git/ref/heads/main')['object']['sha'] != sha:
        raise ValueError('MAIN')
    runs = get_json('/actions/workflows/repository-audit.yml/runs?head_sha=' + sha
                    + '&event=push&status=completed&per_page=100')['workflow_runs']
    if not any(r.get('head_sha') == sha and r.get('head_branch') == 'main'
               and r.get('event') == 'push' and r.get('status') == 'completed'
               and r.get('conclusion') == 'success'
               and r.get('head_repository', {}).get('full_name') == REPO for r in runs):
        raise ValueError('AUDIT')
    # Recheck moving main after reading audit evidence.
    if get_json('/git/ref/heads/main')['object']['sha'] != sha:
        raise ValueError('MAIN_DRIFT')


def normalize(deployments, versions, target):
    if target not in (INVENTORY, DEPLOYMENT):
        raise ValueError('TARGET')
    if not isinstance(deployments, list) or not isinstance(versions, list):
        raise ValueError('SCHEMA')
    if len(deployments) > 100 or len(versions) > 1000:
        raise ValueError('BOUND')
    nums = set()
    for v in versions:
        n = v.get('versionNumber')
        if type(n) is not int or n <= 0 or n in nums:
            raise ValueError('VERSION_SCHEMA')
        nums.add(n)
    rows, seen = [], set()
    for d in deployments:
        identity, n = d.get('deploymentId'), d.get('versionNumber')
        if not isinstance(identity, str) or not re.fullmatch('[A-Za-z0-9_-]{20,200}', identity) or identity in seen:
            raise ValueError('DEPLOYMENT_SCHEMA')
        seen.add(identity)
        if n is not None and (type(n) is not int or n <= 0):
            raise ValueError('VERSION_SCHEMA')
        if target == INVENTORY or identity == target:
            rows.append({'deployment_id': identity, 'version_number': n,
                         'listed_version_corroborated': n in nums,
                         'reference_version_10_match': identity == DEPLOYMENT and n == 10 and n in nums,
                         'type': 'UNKNOWN_CLI_OMITS_ENTRY_POINTS',
                         'endpoint': 'UNKNOWN_CLI_OMITS_ENTRY_POINTS',
                         'owner_reference_url': OWNER_URL if identity == DEPLOYMENT else None,
                         'endpoint_verification': 'OWNER_SUPPLIED_NOT_PROVIDER_VERIFIED'})
    return {'schema': 'H3_APPS_SCRIPT_READONLY_DEPLOYMENT_AUDIT_V1',
            'status': 'HOLD', 'script_id': SCRIPT, 'deployments': rows,
            'metadata_reference_match': any(r['reference_version_10_match'] for r in rows),
            'versioned_source_sha256': None,
            'source_provenance': 'UNKNOWN_VERSIONED_CONTENT_NOT_READ',
            'known_good_rollback': False,
            'open_gates': ['VERSIONED_SOURCE_IDENTITY', 'PROVIDER_ENDPOINT_TYPE', 'OWNER_REACHABILITY', 'KNOWN_GOOD_SIGNOFF']}


def execute():
    checked('IMMUTABLE_MAIN_OR_AUDIT_GUARD', guard)
    target = os.environ.get('AUDIT_TARGET', '')
    if target not in (INVENTORY, DEPLOYMENT):
        raise Diagnostic('TARGET_OR_PINNED_CLI_VERSION', 'INVALID_VALUE')
    clean = {k: os.environ[k] for k in ('PATH', 'HOME', 'SYSTEMROOT') if k in os.environ}
    version = checked('TARGET_OR_PINNED_CLI_VERSION', lambda: subprocess.run(
        ['clasp', '--version'], env=clean, capture_output=True,
        text=True, timeout=10, check=True).stdout.strip())
    if version != '3.4.0':
        raise Diagnostic('TARGET_OR_PINNED_CLI_VERSION', 'INVALID_VALUE')
    secret = checked('CREDENTIAL_PRESENCE_OR_JSON_SCHEMA',
                     lambda: json.loads(os.environ.pop('CLASPRC_JSON', '')))
    if not isinstance(secret, dict) or not secret:
        raise Diagnostic('CREDENTIAL_PRESENCE_OR_JSON_SCHEMA', 'INVALID_VALUE')

    def inventory():
        with tempfile.TemporaryDirectory(prefix='h3-readonly-') as tmp:
            auth = Path(tmp) / '.clasprc.json'
            fd = os.open(auth, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'w') as handle:
                json.dump(secret, handle)
            outputs = []
            for command, stage in (('list-deployments', 'LIST_DEPLOYMENTS_COMMAND'),
                                   ('list-versions', 'LIST_VERSIONS_COMMAND')):
                # Only these fixed nonmutating commands; never forward diagnostics.
                result = checked(stage, lambda: subprocess.run(
                    ['clasp', '--auth', str(auth), '--json', command, SCRIPT],
                    env=clean, capture_output=True, timeout=45, check=True))
                if len(result.stdout) > MAX_BYTES or len(result.stderr) > MAX_BYTES:
                    raise Diagnostic('CLI_RESPONSE_JSON_OR_BOUNDS', 'OUTPUT_BOUND')
                outputs.append(checked('CLI_RESPONSE_JSON_OR_BOUNDS',
                                       lambda: json.loads(result.stdout)))
            return checked('METADATA_NORMALIZATION', lambda: normalize(*outputs, target))

    evidence = checked('CREDENTIAL_FILE_LIFECYCLE', inventory)
    del secret
    checked('SAFE_OUTPUT_FAILURE', lambda: emit(evidence))


def emit(evidence):
    raw = json.dumps(evidence, sort_keys=True)
    if len(raw) > 65536:
        raise ValueError('SUMMARY_BOUND')
    print(raw)
    summary = os.environ.get('GITHUB_STEP_SUMMARY')
    if summary:
        with open(summary, 'a', encoding='utf-8') as handle:
            handle.write('```json\n' + raw + '\n```\n')


def report_failure(failure):
    # Separate best-effort sinks: a broken summary must never cause a traceback
    # or erase the original verified failure stage by recursively calling emit.
    safe = Diagnostic(failure.stage, failure.code)
    evidence = {'schema': 'H3_APPS_SCRIPT_READONLY_DEPLOYMENT_AUDIT_V1',
                'status': 'HOLD', 'reason': 'GUARD_PERMISSION_OR_METADATA_UNAVAILABLE',
                'diagnostic_stage': safe.stage, 'diagnostic_code': safe.code,
                'known_good_rollback': False}
    raw = json.dumps(evidence, sort_keys=True)
    try:
        print(raw)
    except Exception:
        pass
    try:
        summary = os.environ.get('GITHUB_STEP_SUMMARY')
        if summary:
            with open(summary, 'a', encoding='utf-8') as handle:
                handle.write('```json\n' + raw + '\n```\n')
    except Exception:
        pass


def self_test():
    import unittest
    from unittest.mock import patch
    import contextlib
    import io
    class Fixtures(unittest.TestCase):
        def test_reference(self):
            e = normalize([{'deploymentId': DEPLOYMENT, 'versionNumber': 10,
                            'description': 'PRIVATE_CANARY'}], [{'versionNumber': 10}], DEPLOYMENT)
            self.assertTrue(e['metadata_reference_match'])
            self.assertEqual(e['status'], 'HOLD')
            self.assertFalse(e['known_good_rollback'])
            self.assertIsNone(e['versioned_source_sha256'])
            self.assertNotIn('PRIVATE_CANARY', json.dumps(e))
            self.assertEqual(e['deployments'][0]['owner_reference_url'], OWNER_URL)
        def test_mismatch(self):
            for n, versions in [(11, [{'versionNumber': 11}]), (10, [])]:
                self.assertFalse(normalize([{'deploymentId': DEPLOYMENT, 'versionNumber': n}], versions, DEPLOYMENT)['metadata_reference_match'])
        def test_invalid(self):
            for target in ('', OWNER_URL, OWNER_URL.replace('/exec', '/dev'), ':run', 'HEAD'):
                with self.assertRaises(ValueError):
                    normalize([], [], target)
            for d, v in [({}, []), ([], {}), ([{'deploymentId': DEPLOYMENT, 'versionNumber': True}], [])]:
                with self.assertRaises(ValueError):
                    normalize(d, v, INVENTORY)
        def test_head_not_version(self):
            e = normalize([{'deploymentId': DEPLOYMENT}], [], INVENTORY)
            self.assertFalse(e['metadata_reference_match'])
        def test_guard(self):
            sha = 'a' * 40
            env = {'GITHUB_SHA': sha, 'GITHUB_REPOSITORY': REPO,
                   'GITHUB_EVENT_NAME': 'workflow_dispatch', 'GITHUB_REF': 'refs/heads/main',
                   'GITHUB_RUN_ATTEMPT': '1'}
            audit = {'workflow_runs': [{'head_sha': sha, 'head_branch': 'main',
                     'event': 'push', 'status': 'completed', 'conclusion': 'success',
                     'head_repository': {'full_name': REPO}}]}
            head = {'object': {'sha': sha}}
            with patch.dict(os.environ, env, clear=True), patch.object(Path, 'read_text', return_value=json.dumps({'scriptId': SCRIPT})), patch.object(subprocess, 'check_output', return_value=sha):
                with patch(__name__ + '.get_json', side_effect=[head, audit, head]):
                    guard()
                for outputs in ([head, {'workflow_runs': []}], [head, audit, {'object': {'sha': 'b' * 40}}]):
                    with patch(__name__ + '.get_json', side_effect=outputs), self.assertRaises(ValueError):
                        guard()
        def test_permission_failure_redacted(self):
            with patch(__name__ + '.guard', side_effect=PermissionError('PRIVATE_CANARY')), patch.object(sys, 'argv', ['helper', 'execute']), patch.dict(os.environ, {}, clear=True):
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    self.assertEqual(main(), 1)
                self.assertNotIn('PRIVATE_CANARY', output.getvalue())
                self.assertEqual(json.loads(output.getvalue())['status'], 'HOLD')
        def test_failure_matrix(self):
            from types import SimpleNamespace
            import builtins
            canaries = ['PRIVATE_CANARY_EXCEPTION', 'PRIVATE_CANARY_STDOUT',
                        'PRIVATE_CANARY_STDERR', 'PRIVATE_CANARY_JSON',
                        'PRIVATE_CANARY_SECRET', 'PRIVATE_CANARY_SUMMARY']
            version = SimpleNamespace(stdout='3.4.0')
            deployment = SimpleNamespace(stdout=json.dumps([
                {'deploymentId': DEPLOYMENT, 'versionNumber': 10,
                 'description': canaries[1]}]).encode(), stderr=canaries[2].encode())
            versions = SimpleNamespace(stdout=b'[{"versionNumber":10}]', stderr=b'')
            failed = subprocess.CalledProcessError(1, canaries[0],
                       output=canaries[1], stderr=canaries[2])
            timeout = subprocess.TimeoutExpired(canaries[0], 45,
                        output=canaries[1], stderr=canaries[2])
            cases = [
                ('guard', 'IMMUTABLE_MAIN_OR_AUDIT_GUARD', 'OPERATION_FAILED'),
                ('version', 'TARGET_OR_PINNED_CLI_VERSION', 'INVALID_VALUE'),
                ('version_timeout', 'TARGET_OR_PINNED_CLI_VERSION', 'TIMEOUT'),
                ('missing_auth', 'CREDENTIAL_PRESENCE_OR_JSON_SCHEMA', 'INVALID_JSON'),
                ('bad_auth', 'CREDENTIAL_PRESENCE_OR_JSON_SCHEMA', 'INVALID_JSON'),
                ('auth_schema', 'CREDENTIAL_PRESENCE_OR_JSON_SCHEMA', 'INVALID_VALUE'),
                ('deployments', 'LIST_DEPLOYMENTS_COMMAND', 'COMMAND_FAILED'),
                ('versions', 'LIST_VERSIONS_COMMAND', 'COMMAND_FAILED'),
                ('deployments_timeout', 'LIST_DEPLOYMENTS_COMMAND', 'TIMEOUT'),
                ('versions_timeout', 'LIST_VERSIONS_COMMAND', 'TIMEOUT'),
                ('deployments_json', 'CLI_RESPONSE_JSON_OR_BOUNDS', 'INVALID_JSON'),
                ('versions_json', 'CLI_RESPONSE_JSON_OR_BOUNDS', 'INVALID_JSON'),
                ('stdout_bound', 'CLI_RESPONSE_JSON_OR_BOUNDS', 'OUTPUT_BOUND'),
                ('stderr_bound', 'CLI_RESPONSE_JSON_OR_BOUNDS', 'OUTPUT_BOUND'),
                ('schema', 'METADATA_NORMALIZATION', 'INVALID_VALUE'),
                ('summary', 'SAFE_OUTPUT_FAILURE', 'OPERATION_FAILED'),
                ('auth_file', 'CREDENTIAL_FILE_LIFECYCLE', 'OPERATION_FAILED'),
            ]
            for case, stage, code in cases:
                with self.subTest(case=case), tempfile.TemporaryDirectory() as tmp:
                    summary = Path(tmp) / 'summary'
                    env = {'AUDIT_TARGET': DEPLOYMENT, 'GITHUB_STEP_SUMMARY': str(summary),
                           'CLASPRC_JSON': json.dumps({'fake': canaries[4]})}
                    if case == 'missing_auth':
                        del env['CLASPRC_JSON']
                    elif case == 'bad_auth':
                        env['CLASPRC_JSON'] = canaries[3]
                    elif case == 'auth_schema':
                        env['CLASPRC_JSON'] = '[]'
                    results = [version, deployment, versions]
                    if case == 'version':
                        results[0] = SimpleNamespace(stdout=canaries[1])
                    elif case == 'version_timeout':
                        results[0] = timeout
                    elif case in ('deployments', 'deployments_timeout'):
                        results[1] = timeout if case.endswith('timeout') else failed
                    elif case in ('versions', 'versions_timeout'):
                        results[2] = timeout if case.endswith('timeout') else failed
                    elif case in ('deployments_json', 'versions_json'):
                        results[1 if case.startswith('deployments') else 2] = SimpleNamespace(stdout=canaries[3].encode(), stderr=b'')
                    elif case in ('stdout_bound', 'stderr_bound'):
                        results[1] = SimpleNamespace(stdout=b'x' * (MAX_BYTES + 1) if case == 'stdout_bound' else b'[]',
                                                     stderr=b'x' * (MAX_BYTES + 1) if case == 'stderr_bound' else b'')
                    elif case == 'schema':
                        results[1] = SimpleNamespace(stdout=b'{}', stderr=b'')
                    original_open, original_os_open = builtins.open, os.open
                    def safe_open(path, *args, **kwargs):
                        if case == 'summary' and str(path) == str(summary):
                            raise OSError(canaries[5])
                        return original_open(path, *args, **kwargs)
                    def fake_auth_open(path, *args, **kwargs):
                        if case == 'auth_file' and str(path).endswith('.clasprc.json'):
                            raise OSError(canaries[0])
                        return original_os_open(path, *args, **kwargs)
                    out, err = io.StringIO(), io.StringIO()
                    with patch.dict(os.environ, env, clear=True), patch.object(sys, 'argv', ['helper', 'execute']), patch(__name__ + '.guard', side_effect=PermissionError(canaries[0]) if case == 'guard' else None), patch.object(subprocess, 'run', side_effect=results) as run, patch('builtins.open', side_effect=safe_open), patch.object(os, 'open', side_effect=fake_auth_open), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                        self.assertEqual(main(), 1)
                        if case == 'guard':
                            run.assert_not_called()
                            self.assertEqual(os.environ['CLASPRC_JSON'], env['CLASPRC_JSON'])
                    summary_text = summary.read_text() if summary.exists() else ''
                    for canary in canaries:
                        self.assertNotIn(canary, out.getvalue() + err.getvalue() + summary_text)
                    evidence = json.loads(out.getvalue().splitlines()[-1])
                    self.assertEqual((evidence['diagnostic_stage'], evidence['diagnostic_code']), (stage, code))
                    self.assertEqual(evidence['status'], 'HOLD')
                    self.assertFalse(evidence['known_good_rollback'])
                    self.assertEqual(err.getvalue(), '')
        def test_diagnostic_allowlist(self):
            out = io.StringIO()
            with patch.dict(os.environ, {}, clear=True), contextlib.redirect_stdout(out):
                report_failure(Diagnostic('PRIVATE_CANARY_STAGE', 'PRIVATE_CANARY_CODE'))
            self.assertNotIn('PRIVATE_CANARY', out.getvalue())
            result = json.loads(out.getvalue())
            self.assertIn(result['diagnostic_stage'], STAGES)
            self.assertIn(result['diagnostic_code'], CODES)
    result = unittest.TextTestRunner().run(unittest.defaultTestLoader.loadTestsFromTestCase(Fixtures))
    return 0 if result.wasSuccessful() else 1


def main():
    if sys.argv[1:] == ['self-test']:
        return self_test()
    try:
        if sys.argv[1:] == ['guard']:
            checked('IMMUTABLE_MAIN_OR_AUDIT_GUARD', guard)
        elif sys.argv[1:] == ['execute']:
            execute()
        else:
            raise Diagnostic('INVOCATION_MODE', 'INVALID_VALUE')
        return 0
    except Diagnostic as failure:
        report_failure(failure)
        return 1
    except Exception:
        report_failure(Diagnostic('INVOCATION_MODE', 'OPERATION_FAILED'))
        return 1


if __name__ == '__main__':
    sys.exit(main())
