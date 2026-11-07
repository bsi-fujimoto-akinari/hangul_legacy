#!/usr/bin/env python3
"""Manual inventory only. Metadata never establishes known-good rollback.

The repository is public: GitHub guard GETs deliberately use no credential and
need no Actions token permission. Permission/rate failures stop before auth.
Run `self-test` for offline fixtures; it never reads credentials or the network.

`execute-refresh-diagnostic` is a separate opt-in mode requiring fresh owner
approval for its potential credentialed OAuth refresh POST. The existing manual
workflow calls `execute` and does NOT opt in. No dispatch is authorized by source
preparation. A refresh success proves neither deployment access nor CLI scopes;
invalid_grant does not prove expiry. No refreshed token is saved or used.

Contracts: Google identity/protocols/oauth2/web-server (refresh access token),
RFC 6749 sections 5.1/5.2/6, and google/clasp commit
efd052467c651f64dfce07aa6e44e21353da9cf2 src/auth/file_credential_store.ts.
"""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
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
                   'INVALID_JSON', 'INVALID_VALUE', 'OUTPUT_BOUND',
                   'AUTH_ENVELOPE_INVALID', 'AUTH_DEFAULT_MISSING', 'AUTH_ENVELOPE_UNKNOWN',
                   'REFRESH_INVALID_GRANT', 'REFRESH_INVALID_CLIENT',
                   'REFRESH_SUCCEEDED_LIST_STILL_FAILED', 'REFRESH_NOT_APPLICABLE',
                   'COMMAND_FAILED_UNKNOWN'})
REFRESH_URL = 'https://oauth2.googleapis.com/token'
REFRESH_MAX_BYTES = 8192
REFRESH_TIMEOUT = 3
REFRESH_DEADLINE = 5


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


def credential_shape(secret):
    # clasp 3.4.0 FileCredentialStore.load('default') precedence, offline only.
    # Recognizing a shape never establishes token validity or provider access.
    def nonempty_text(value):
        return isinstance(value, str) and bool(value.strip())

    if not isinstance(secret, dict) or not secret:
        return 'AUTH_ENVELOPE_INVALID'
    tokens = secret.get('tokens')
    if tokens is not None and not isinstance(tokens, dict):
        return 'AUTH_ENVELOPE_INVALID'
    if isinstance(tokens, dict) and tokens.get('default'):
        credential = tokens['default']
        valid = (isinstance(credential, dict)
                 and credential.get('type') == 'authorized_user'
                 and all(nonempty_text(credential.get(key)) for key in
                         ('client_id', 'client_secret', 'refresh_token')))
        return None if valid else 'AUTH_ENVELOPE_INVALID'
    # Named-only V3 may still fall back to a supported V1 default.
    if secret.get('token') and secret.get('oauth2ClientSettings'):
        token, settings = secret['token'], secret['oauth2ClientSettings']
        valid = (isinstance(token, dict) and isinstance(settings, dict)
                 and nonempty_text(token.get('refresh_token'))
                 and nonempty_text(settings.get('clientId'))
                 and nonempty_text(settings.get('clientSecret')))
        return None if valid else 'AUTH_ENVELOPE_INVALID'
    if secret.get('access_token'):
        return None if nonempty_text(secret['access_token']) else 'AUTH_ENVELOPE_INVALID'
    if isinstance(tokens, dict):
        return 'AUTH_DEFAULT_MISSING'
    if 'token' in secret or 'oauth2ClientSettings' in secret:
        return 'AUTH_ENVELOPE_INVALID'
    return 'AUTH_ENVELOPE_UNKNOWN'


def refresh_fields(secret):
    # Same default precedence as pinned clasp; never borrow a named/other client.
    if credential_shape(secret) is not None:
        return None
    tokens = secret.get('tokens')
    if isinstance(tokens, dict) and tokens.get('default'):
        credential = tokens['default']
        values = tuple(credential[key] for key in
                       ('client_id', 'client_secret', 'refresh_token'))
    elif secret.get('token') and secret.get('oauth2ClientSettings'):
        settings = secret['oauth2ClientSettings']
        values = (settings['clientId'], settings['clientSecret'],
                  secret['token']['refresh_token'])
    else:
        # V1 global requires clasp's implicit built-in client. Do not guess it,
        # even if a top-level refresh_token is present; access-only is also N/A.
        return None
    if any(not isinstance(v, str) or not v.strip() or len(v) > 4096 for v in values):
        return None
    return dict(zip(('client_id', 'client_secret', 'refresh_token'), values))


def refresh_diagnostic(secret):
    # Called once only after opt-in LIST_DEPLOYMENTS_COMMAND/COMMAND_FAILED.
    # Every path returns a fixed label; no raw response/exception may escape.
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            return None

    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError()
            result[key] = value
        return result

    try:
        fields = refresh_fields(secret)
        if fields is None:
            return 'REFRESH_NOT_APPLICABLE'
        fields['grant_type'] = 'refresh_token'
        body = urllib.parse.urlencode(fields).encode('ascii')
        del fields
        if len(body) > 65536:
            return 'COMMAND_FAILED_UNKNOWN'
        request = urllib.request.Request(REFRESH_URL, data=body, method='POST',
                    headers={'Content-Type': 'application/x-www-form-urlencoded',
                             'Accept': 'application/json'})
        del body
        # Disable environment proxy routing and redirects. urllib has no retry.
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect)
        deadline = time.monotonic() + REFRESH_DEADLINE
        try:
            response = opener.open(request, timeout=REFRESH_TIMEOUT)
        except urllib.error.HTTPError as failure:
            response = failure
        del request, opener
        with response:
            status = response.code
            if status not in (200, 400):
                return 'COMMAND_FAILED_UNKNOWN'
            if response.headers.get_content_type() != 'application/json':
                return 'COMMAND_FAILED_UNKNOWN'
            length = response.headers.get('Content-Length')
            if length is not None and (not length.isascii() or not length.isdecimal()
                                       or int(length) > REFRESH_MAX_BYTES):
                return 'COMMAND_FAILED_UNKNOWN'
            raw = b''
            # read1 avoids an unbounded wait for a full buffer on a trickling
            # peer. Each socket operation also has the short timeout above.
            while len(raw) <= REFRESH_MAX_BYTES:
                if time.monotonic() >= deadline:
                    return 'COMMAND_FAILED_UNKNOWN'
                chunk = response.read1(REFRESH_MAX_BYTES + 1 - len(raw))
                if not chunk:
                    break
                raw += chunk
            if len(raw) > REFRESH_MAX_BYTES or time.monotonic() >= deadline:
                return 'COMMAND_FAILED_UNKNOWN'
        payload = json.loads(raw.decode('utf-8'), object_pairs_hook=unique_pairs,
                             parse_constant=lambda _: None)
        del raw, chunk, response
        if not isinstance(payload, dict):
            return 'COMMAND_FAILED_UNKNOWN'
        if status == 400:
            allowed = {'error', 'error_description', 'error_uri', 'error_subtype'}
            if (not set(payload) <= allowed
                    or not all(isinstance(v, str) for v in payload.values())):
                return 'COMMAND_FAILED_UNKNOWN'
            # Numeric status alone, arbitrary text and unknown errors stay UNKNOWN.
            return {'invalid_grant': 'REFRESH_INVALID_GRANT',
                    'invalid_client': 'REFRESH_INVALID_CLIENT'}.get(
                        payload.get('error'), 'COMMAND_FAILED_UNKNOWN')
        if (set(payload) <= {'access_token', 'expires_in', 'token_type', 'scope'}
                and isinstance(payload.get('access_token'), str)
                and 0 < len(payload['access_token']) <= 4096
                and type(payload.get('expires_in')) is int
                and 0 < payload['expires_in'] <= 86400
                and payload.get('token_type') == 'Bearer'
                and ('scope' not in payload or isinstance(payload['scope'], str))):
            return 'REFRESH_SUCCEEDED_LIST_STILL_FAILED'
        return 'COMMAND_FAILED_UNKNOWN'
    except Exception:
        return 'COMMAND_FAILED_UNKNOWN'


def execute(refresh_enabled=False):
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
    shape_error = credential_shape(secret)
    if shape_error:
        raise Diagnostic('CREDENTIAL_PRESENCE_OR_JSON_SCHEMA', shape_error)

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
                try:
                    result = checked(stage, lambda: subprocess.run(
                        ['clasp', '--auth', str(auth), '--json', command, SCRIPT],
                        env=clean, capture_output=True, timeout=45, check=True))
                except Diagnostic as failure:
                    if (refresh_enabled and stage == 'LIST_DEPLOYMENTS_COMMAND'
                            and failure.code == 'COMMAND_FAILED'):
                        raise Diagnostic(stage, refresh_diagnostic(secret)) from None
                    raise
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
    if safe.code.startswith('REFRESH_') or safe.code == 'COMMAND_FAILED_UNKNOWN':
        evidence.update(versioned_source_sha256=None,
                        source_provenance='UNKNOWN_VERSIONED_CONTENT_NOT_READ',
                        open_gates=['VERSIONED_SOURCE_IDENTITY', 'PROVIDER_ENDPOINT_TYPE',
                                    'OWNER_REACHABILITY', 'KNOWN_GOOD_SIGNOFF'])
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
                ('auth_schema', 'CREDENTIAL_PRESENCE_OR_JSON_SCHEMA', 'AUTH_ENVELOPE_INVALID'),
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
                           'CLASPRC_JSON': json.dumps({'access_token': canaries[4]})}
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
        def test_envelopes(self):
            from types import SimpleNamespace
            value = 'PRIVATE_CANARY_CREDENTIAL'
            modern = {'type': 'authorized_user', 'client_id': value,
                      'client_secret': value, 'refresh_token': value}
            local = {'token': {'refresh_token': value},
                     'oauth2ClientSettings': {'clientId': value, 'clientSecret': value}}
            for envelope in ({'tokens': {'default': modern}}, local,
                             {'access_token': value}, dict(local, tokens={'named': modern})):
                self.assertIsNone(credential_shape(envelope))
            for envelope, code in [
                ({'tokens': {'named': modern}}, 'AUTH_DEFAULT_MISSING'),
                ({'tokens': {}}, 'AUTH_DEFAULT_MISSING'),
                ({'tokens': {'default': value}}, 'AUTH_ENVELOPE_INVALID'),
                ({'tokens': []}, 'AUTH_ENVELOPE_INVALID'),
                ({'token': value}, 'AUTH_ENVELOPE_INVALID'),
                ({'access_token': True}, 'AUTH_ENVELOPE_INVALID'),
                ({'unsupported': value}, 'AUTH_ENVELOPE_UNKNOWN'),
                ({}, 'AUTH_ENVELOPE_INVALID'), ([], 'AUTH_ENVELOPE_INVALID')]:
                self.assertEqual(credential_shape(envelope), code)
                with tempfile.TemporaryDirectory() as tmp:
                    summary = Path(tmp) / 'summary'
                    env = {'CLASPRC_JSON': json.dumps(envelope), 'AUDIT_TARGET': INVENTORY,
                           'GITHUB_STEP_SUMMARY': str(summary), 'PRIVATE_CANARY_ENV': value}
                    out, err = io.StringIO(), io.StringIO()
                    with patch.dict(os.environ, env, clear=True), patch.object(sys, 'argv', ['helper', 'execute']), patch(__name__ + '.guard'), patch.object(subprocess, 'run', return_value=SimpleNamespace(stdout='3.4.0')) as run, contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                        self.assertEqual(main(), 1)
                        self.assertEqual(run.call_count, 1)  # version only; no auth CLI
                    self.assertEqual(json.loads(out.getvalue())['diagnostic_code'], code)
                    self.assertNotIn('PRIVATE_CANARY', out.getvalue() + err.getvalue() + summary.read_text())

        def test_ambiguous_provider_errors(self):
            # Pinned clasp has no established structured error output contract.
            # Keep COMMAND_FAILED; 401/403/free text must not assert root causes.
            for payload in ('401', '403', '500', 'API_DISABLED',
                            '{"error":{"code":403,"status":"PERMISSION_DENIED"}}',
                            'PRIVATE_CANARY_CHILD'):
                failure = subprocess.CalledProcessError(1, 'PRIVATE_CANARY_COMMAND',
                            output=payload, stderr=payload)
                with self.assertRaises(Diagnostic) as caught:
                    checked('LIST_DEPLOYMENTS_COMMAND', lambda: (_ for _ in ()).throw(failure))
                self.assertEqual(caught.exception.code, 'COMMAND_FAILED')
                out = io.StringIO()
                with patch.dict(os.environ, {}, clear=True), contextlib.redirect_stdout(out):
                    report_failure(caught.exception)
                self.assertNotIn(payload, out.getvalue())
                self.assertNotIn('PRIVATE_CANARY', out.getvalue())

        def test_diagnostic_allowlist(self):
            out = io.StringIO()
            with patch.dict(os.environ, {}, clear=True), contextlib.redirect_stdout(out):
                report_failure(Diagnostic('PRIVATE_CANARY_STAGE', 'PRIVATE_CANARY_CODE'))
            self.assertNotIn('PRIVATE_CANARY', out.getvalue())
            result = json.loads(out.getvalue())
            self.assertIn(result['diagnostic_stage'], STAGES)
            self.assertIn(result['diagnostic_code'], CODES)

        def test_refresh_envelope_precedence(self):
            modern = {'type': 'authorized_user', 'client_id': 'SYNTHETIC_CLIENT',
                      'client_secret': 'SYNTHETIC_SECRET', 'refresh_token': 'SYNTHETIC_REFRESH'}
            local = {'token': {'refresh_token': 'SYNTHETIC_LOCAL_REFRESH'},
                     'oauth2ClientSettings': {'clientId': 'SYNTHETIC_LOCAL_CLIENT',
                                              'clientSecret': 'SYNTHETIC_LOCAL_SECRET'}}
            for envelope in ({'tokens': {'default': modern}},
                             dict(local, tokens={'default': modern})):
                self.assertEqual(refresh_fields(envelope)['refresh_token'], modern['refresh_token'])
            for envelope in (local, dict(local, tokens={'named': modern})):
                self.assertEqual(refresh_fields(envelope)['client_id'], 'SYNTHETIC_LOCAL_CLIENT')
            for envelope in ({'access_token': 'SYNTHETIC_ACCESS'},
                             {'access_token': 'SYNTHETIC_ACCESS', 'refresh_token': 'SYNTHETIC_REFRESH'},
                             dict(local, tokens={'default': 'SYNTHETIC_INVALID'}),
                             {'tokens': {'named': modern}}, [], {}):
                with patch.object(urllib.request, 'build_opener') as build:
                    self.assertEqual(refresh_diagnostic(envelope), 'REFRESH_NOT_APPLICABLE')
                    build.assert_not_called()

        def test_refresh_response_matrix(self):
            from email.message import Message
            from types import SimpleNamespace
            from unittest.mock import Mock
            secret = {'tokens': {'default': {'type': 'authorized_user',
                      'client_id': 'SYNTHETIC_CLIENT', 'client_secret': 'SYNTHETIC_SECRET',
                      'refresh_token': 'SYNTHETIC_REFRESH'}}}
            success = {'access_token': 'SYNTHETIC_RESPONSE_CANARY',
                       'expires_in': 3600, 'token_type': 'Bearer', 'scope': 'SYNTHETIC_SCOPE'}
            cases = [
                (200, success, 'REFRESH_SUCCEEDED_LIST_STILL_FAILED'),
                (400, {'error': 'invalid_grant'}, 'REFRESH_INVALID_GRANT'),
                (400, {'error': 'invalid_client', 'error_description': 'SYNTHETIC_秘密'}, 'REFRESH_INVALID_CLIENT'),
                (400, {'error': 'unknown', 'error_description': 'invalid_grant'}, 'COMMAND_FAILED_UNKNOWN'),
                (401, {'error': 'invalid_client'}, 'COMMAND_FAILED_UNKNOWN'),
                (403, {'error': 'invalid_grant'}, 'COMMAND_FAILED_UNKNOWN'),
                (429, {'error': 'invalid_grant'}, 'COMMAND_FAILED_UNKNOWN'),
                (500, {'error': 'invalid_client'}, 'COMMAND_FAILED_UNKNOWN'),
                (302, success, 'COMMAND_FAILED_UNKNOWN'),
                (307, success, 'COMMAND_FAILED_UNKNOWN'),
                (200, dict(success, error='invalid_grant'), 'COMMAND_FAILED_UNKNOWN'),
                (400, dict(success, error='invalid_grant'), 'COMMAND_FAILED_UNKNOWN'),
                (200, dict(success, expires_in=True), 'COMMAND_FAILED_UNKNOWN'),
                (200, dict(success, token_type='SYNTHETIC_OTHER'), 'COMMAND_FAILED_UNKNOWN'),
                (200, {}, 'COMMAND_FAILED_UNKNOWN'),
                (200, [], 'COMMAND_FAILED_UNKNOWN'),
                (400, {'error': {'error': 'invalid_grant'}}, 'COMMAND_FAILED_UNKNOWN'),
                (400, {'error': 'invalid_grant', 'extra': 'SYNTHETIC'}, 'COMMAND_FAILED_UNKNOWN'),
            ]
            for status, payload, expected in cases:
                for http_error in (False, True) if status == 400 else (False,):
                    with self.subTest(status=status, expected=expected, http_error=http_error):
                        headers = Message()
                        headers['Content-Type'] = 'application/json'
                        raw = json.dumps(payload).encode()
                        response = io.BytesIO(raw)
                        response.code, response.headers = status, headers
                        error = urllib.error.HTTPError(REFRESH_URL, status, 'SYNTHETIC_ERROR', headers, response)
                        open_call = Mock(side_effect=error) if http_error else Mock(return_value=response)
                        with tempfile.TemporaryDirectory() as tmp:
                            summary = Path(tmp) / 'summary'
                            out, err = io.StringIO(), io.StringIO()
                            with patch.dict(os.environ, {'GITHUB_STEP_SUMMARY': str(summary)}, clear=True), patch.object(urllib.request, 'build_opener', return_value=SimpleNamespace(open=open_call)), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                                label = refresh_diagnostic(secret)
                                self.assertEqual(label, expected)
                                report_failure(Diagnostic('LIST_DEPLOYMENTS_COMMAND', label))
                            sinks = out.getvalue() + err.getvalue() + summary.read_text()
                            self.assertNotIn('SYNTHETIC', sinks)
                            self.assertNotIn('秘密', sinks)
                            evidence = json.loads(out.getvalue())
                            self.assertEqual(evidence['status'], 'HOLD')
                            self.assertIsNone(evidence['versioned_source_sha256'])
                            self.assertFalse(evidence['known_good_rollback'])
                        open_call.assert_called_once()
                        request = open_call.call_args.args[0]
                        self.assertEqual(request.full_url, REFRESH_URL)
                        self.assertEqual(request.get_method(), 'POST')
                        self.assertNotIn('SYNTHETIC', request.full_url)
                        form = urllib.parse.parse_qs(request.data.decode())
                        self.assertEqual(set(form), {'client_id', 'client_secret', 'refresh_token', 'grant_type'})
                        self.assertEqual(form['grant_type'], ['refresh_token'])
                        self.assertEqual(open_call.call_args.kwargs, {'timeout': REFRESH_TIMEOUT})
                        self.assertTrue(response.closed)

        def test_refresh_bounds_network_and_json(self):
            from email.message import Message
            from types import SimpleNamespace
            from unittest.mock import Mock
            secret = {'token': {'refresh_token': 'SYNTHETIC_REFRESH'},
                      'oauth2ClientSettings': {'clientId': 'SYNTHETIC_CLIENT', 'clientSecret': 'SYNTHETIC_SECRET'}}
            for raw, content_type, length in [
                (b'not json SYNTHETIC', 'application/json', None),
                (b'\xff', 'application/json', None),
                (b'x' * (REFRESH_MAX_BYTES + 1), 'application/json', None),
                (b'{"error":"invalid_grant","error":"invalid_client"}', 'application/json', None),
                (b'{"error":"invalid_grant"}', 'text/html', None),
                (b'{}', 'application/json', str(REFRESH_MAX_BYTES + 1)),
                (b'{}', 'application/json', 'SYNTHETIC'),
            ]:
                headers = Message()
                headers['Content-Type'] = content_type
                if length is not None:
                    headers['Content-Length'] = length
                response = io.BytesIO(raw)
                response.code, response.headers = 400, headers
                call = Mock(return_value=response)
                with patch.object(urllib.request, 'build_opener', return_value=SimpleNamespace(open=call)):
                    self.assertEqual(refresh_diagnostic(secret), 'COMMAND_FAILED_UNKNOWN')
                call.assert_called_once()
                self.assertTrue(response.closed)
            for failure in (TimeoutError('SYNTHETIC'), OSError('SYNTHETIC'),
                            urllib.error.URLError('SYNTHETIC')):
                call = Mock(side_effect=failure)
                with patch.object(urllib.request, 'build_opener', return_value=SimpleNamespace(open=call)):
                    self.assertEqual(refresh_diagnostic(secret), 'COMMAND_FAILED_UNKNOWN')
                call.assert_called_once()
            response = io.BytesIO(b'{"error":"invalid_grant"}')
            response.code, response.headers = 400, headers
            with patch.object(urllib.request, 'build_opener', return_value=SimpleNamespace(open=Mock(return_value=response))), patch.object(time, 'monotonic', side_effect=[0, 6]):
                self.assertEqual(refresh_diagnostic(secret), 'COMMAND_FAILED_UNKNOWN')
            self.assertTrue(response.closed)
            # Exercise the actual redirect rejection policy without transport.
            with patch.object(urllib.request, 'build_opener', return_value=SimpleNamespace(open=Mock(side_effect=OSError()))) as build:
                self.assertEqual(refresh_diagnostic(secret), 'COMMAND_FAILED_UNKNOWN')
            proxy, redirect = build.call_args.args
            self.assertEqual(proxy.proxies, {})
            for status in (301, 302, 303, 307, 308):
                self.assertIsNone(redirect().redirect_request(None, None, status, None, None, None))

        def test_refresh_failure_only_integration(self):
            from types import SimpleNamespace
            secret = {'tokens': {'default': {'type': 'authorized_user',
                      'client_id': 'SYNTHETIC_CLIENT', 'client_secret': 'SYNTHETIC_SECRET',
                      'refresh_token': 'SYNTHETIC_REFRESH'}}}
            failed = subprocess.CalledProcessError(1, 'SYNTHETIC_COMMAND',
                       output=b'SYNTHETIC_STDOUT', stderr=b'SYNTHETIC_STDERR')
            version = SimpleNamespace(stdout='3.4.0')
            positive = SimpleNamespace(stdout=b'[]', stderr=b'')
            timeout = subprocess.TimeoutExpired('SYNTHETIC', 45)
            for mode, case, expected in [
                ('execute-refresh-diagnostic', 'deployments', 1),
                ('execute', 'deployments', 0),
                ('execute-refresh-diagnostic', 'success', 0),
                ('execute-refresh-diagnostic', 'versions', 0),
                ('execute-refresh-diagnostic', 'timeout', 0),
                ('execute-refresh-diagnostic', 'guard', 0),
                ('execute-refresh-diagnostic', 'bad_auth', 0),
            ]:
                with self.subTest(mode=mode, case=case), tempfile.TemporaryDirectory() as tmp:
                    summary = Path(tmp) / 'summary'
                    env = {'CLASPRC_JSON': '[]' if case == 'bad_auth' else json.dumps(secret),
                           'AUDIT_TARGET': INVENTORY, 'GITHUB_STEP_SUMMARY': str(summary)}
                    results = [version, failed if case == 'deployments' else timeout if case == 'timeout' else positive,
                               failed if case == 'versions' else positive]
                    out, err = io.StringIO(), io.StringIO()
                    with patch.dict(os.environ, env, clear=True), patch.object(sys, 'argv', ['helper', mode]), patch(__name__ + '.guard', side_effect=ValueError('SYNTHETIC') if case == 'guard' else None), patch.object(subprocess, 'run', side_effect=results) as run, patch(__name__ + '.refresh_diagnostic', return_value='REFRESH_INVALID_GRANT') as refresh, contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                        self.assertEqual(main(), 0 if case == 'success' else 1)
                    self.assertEqual(refresh.call_count, expected)
                    if expected:
                        self.assertEqual(run.call_count, 2)  # version + list only
                    for call in run.call_args_list:
                        if '--auth' in call.args[0]:
                            self.assertFalse(Path(call.args[0][2]).exists())
                    self.assertNotIn('SYNTHETIC', out.getvalue() + err.getvalue() + summary.read_text())
                    self.assertEqual(err.getvalue(), '')
    import socket
    # Fail before any unexpected real network/process attempt, even in fixtures.
    with patch.dict(os.environ, {}, clear=True), patch.object(socket, 'create_connection', side_effect=AssertionError('OFFLINE_ONLY')), patch.object(urllib.request, 'build_opener', side_effect=AssertionError('OFFLINE_ONLY')), patch.object(urllib.request, 'urlopen', side_effect=AssertionError('OFFLINE_ONLY')), patch.object(subprocess, 'run', side_effect=AssertionError('OFFLINE_ONLY')), patch.object(subprocess, 'check_output', side_effect=AssertionError('OFFLINE_ONLY')):
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
        elif sys.argv[1:] == ['execute-refresh-diagnostic']:
            execute(refresh_enabled=True)
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
