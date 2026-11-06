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
    guard()  # Must succeed before materializing the existing Actions secret.
    target = os.environ.get('AUDIT_TARGET', '')
    if target not in (INVENTORY, DEPLOYMENT):
        raise ValueError('TARGET')
    clean = {k: os.environ[k] for k in ('PATH', 'HOME', 'SYSTEMROOT') if k in os.environ}
    version = subprocess.run(['clasp', '--version'], env=clean, capture_output=True,
                             text=True, timeout=10, check=True).stdout.strip()
    if version != '3.4.0':
        raise ValueError('CLI_VERSION')
    secret = json.loads(os.environ.pop('CLASPRC_JSON', ''))
    if not isinstance(secret, dict) or not secret:
        raise ValueError('AUTH')
    with tempfile.TemporaryDirectory(prefix='h3-readonly-') as tmp:
        auth = Path(tmp) / '.clasprc.json'
        fd = os.open(auth, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as handle:
            json.dump(secret, handle)
        del secret
        outputs = []
        for command in ('list-deployments', 'list-versions'):
            # Only these fixed nonmutating CLI commands; capture all diagnostics.
            result = subprocess.run(['clasp', '--auth', str(auth), '--json', command, SCRIPT],
                                    env=clean, capture_output=True, timeout=45, check=True)
            if len(result.stdout) > MAX_BYTES or len(result.stderr) > MAX_BYTES:
                raise ValueError('BOUND')
            outputs.append(json.loads(result.stdout))
        evidence = normalize(*outputs, target)
    emit(evidence)


def emit(evidence):
    raw = json.dumps(evidence, sort_keys=True)
    if len(raw) > 65536:
        raise ValueError('SUMMARY_BOUND')
    print(raw)
    summary = os.environ.get('GITHUB_STEP_SUMMARY')
    if summary:
        with open(summary, 'a', encoding='utf-8') as handle:
            handle.write('```json\n' + raw + '\n```\n')


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
    result = unittest.TextTestRunner().run(unittest.defaultTestLoader.loadTestsFromTestCase(Fixtures))
    return 0 if result.wasSuccessful() else 1


def main():
    if sys.argv[1:] == ['self-test']:
        return self_test()
    try:
        if sys.argv[1:] == ['guard']:
            guard()
        elif sys.argv[1:] == ['execute']:
            execute()
        else:
            raise ValueError('MODE')
        return 0
    except Exception:
        # Never emit raw errors, subprocess output, auth or source content.
        emit({'schema': 'H3_APPS_SCRIPT_READONLY_DEPLOYMENT_AUDIT_V1',
              'status': 'HOLD', 'reason': 'GUARD_PERMISSION_OR_METADATA_UNAVAILABLE',
              'known_good_rollback': False})
        return 1


if __name__ == '__main__':
    sys.exit(main())
