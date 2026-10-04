import json
import sys

raw = open(sys.argv[1], encoding='utf-8').read()
try:
    envelope = json.loads(raw)
except json.JSONDecodeError:
    stderr = open(sys.argv[5], encoding='utf-8').read()
    combined = (raw + '\n' + stderr).lower()
    category = 'UNCLASSIFIED_INVALID_OUTPUT'
    for marker, code in [
        ('invalid_grant', 'AUTH_INVALID_GRANT'),
        ('permission', 'EXECUTION_PERMISSION_ERROR'),
        ('not authorized', 'EXECUTION_PERMISSION_ERROR'),
        ('api executable', 'API_EXECUTABLE_UNAVAILABLE'),
        ('script function not found', 'API_EXECUTABLE_UNAVAILABLE'),
        ('unable to run script', 'EXECUTION_UNAVAILABLE'),
    ]:
        if marker in combined:
            category = code
            break
    # Never emit raw command output: it may contain credentials or payloads.
    raise SystemExit(
        'CLASP_SOURCE_BINDING_OUTPUT_INVALID: '
        f'category={category}; stdout_bytes={len(raw.encode("utf-8"))}; '
        f'stderr_present={bool(stderr.strip())}'
    ) from None
if not isinstance(envelope, dict):
    raise SystemExit('CLASP_SOURCE_BINDING_ENVELOPE_INVALID')
if envelope.get('error'):
    raise SystemExit('Observability source binding returned an Apps Script error envelope.')
result = envelope.get('response')
if not isinstance(result, dict):
    raise SystemExit('Observability source binding response is not an object.')
expected = {
    'schema': 'H3_OBSERVABILITY_SOURCE_BINDING_RESULT_V1',
    'status': 'PASS',
    'source_sha': sys.argv[2],
    'source_digest': sys.argv[3],
    'source_file_count': int(sys.argv[4]),
}
for key, value in expected.items():
    if result.get(key) != value:
        raise SystemExit(
            f'Observability source binding readback mismatch for {key}: '
            f'{result.get(key)!r} != {value!r}'
        )
print(
    'Observability source binding PASS: '
    f"sha={result['source_sha']}; digest={result['source_digest']}; "
    f"files={result['source_file_count']}"
)
