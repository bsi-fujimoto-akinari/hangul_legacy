var H3_SOURCE_ADAPTER_PATH_ = '/mcp/source-read';

function h3SourceAdapterExactKeys_(value, expected) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('SOURCE_ADAPTER_REQUEST_INVALID');
  }
  var actual = Object.keys(value).sort();
  var wanted = expected.slice().sort();
  if (JSON.stringify(actual) !== JSON.stringify(wanted)) {
    throw new Error('SOURCE_ADAPTER_REQUEST_INVALID');
  }
}

function h3SourceAdapterRequest_(request) {
  h3SourceAdapterExactKeys_(request, [
    'schema',
    'operation',
    'authority_channel',
    'expected_manifest_version_or_null',
    'expected_source_set_id_or_null',
    'selector'
  ]);
  if (request.schema !== 'H3_SOURCE_RESOLVE_REQUEST_V1') {
    throw new Error('SOURCE_ADAPTER_REQUEST_INVALID');
  }
  if ([
    'RESOLVE_OFFICIAL_ITEM',
    'RESOLVE_OFFICIAL_GROUP',
    'QUERY_OFFICIAL_SKILL_SOURCE',
    'RESOLVE_TOWMI_AUTHORING_SOURCE',
    'READ_MANIFEST_RELEASE'
  ].indexOf(request.operation) < 0) {
    throw new Error('SOURCE_ADAPTER_OPERATION_INVALID');
  }
  if (request.authority_channel !== 'ACTIVE' &&
      request.authority_channel !== 'CANDIDATE') {
    throw new Error('SOURCE_ADAPTER_CHANNEL_INVALID');
  }
  if (!request.selector || typeof request.selector !== 'object' ||
      Array.isArray(request.selector) ||
      Object.prototype.hasOwnProperty.call(request.selector, 'consumer_id')) {
    throw new Error('SOURCE_ADAPTER_SELECTOR_INVALID');
  }
  return request;
}

function h3SourceAdapterBaseUrl_(value) {
  value = String(value || '');
  if (!/^https:\/\/[^/?#]+$/.test(value)) {
    throw new Error('SOURCE_ADAPTER_BASE_URL_INVALID');
  }
  return value;
}

function h3SourceAdapterResolveCurrentAppsScript_(request) {
  request = h3SourceAdapterRequest_(request);
  var props = PropertiesService.getScriptProperties();
  var baseUrl = h3SourceAdapterBaseUrl_(
    props.getProperty('H3_SOURCE_ADAPTER_BASE_URL')
  );
  var bearer = String(
    props.getProperty('H3_SOURCE_ADAPTER_BEARER_TOKEN') || ''
  );
  if (!bearer) throw new Error('SOURCE_ADAPTER_TOKEN_MISSING');

  var response = UrlFetchApp.fetch(baseUrl + H3_SOURCE_ADAPTER_PATH_, {
    method: 'post',
    contentType: 'application/json',
    headers: {Authorization: 'Bearer ' + bearer},
    payload: JSON.stringify(request),
    muteHttpExceptions: true
  });
  if (response.getResponseCode() !== 200) {
    throw new Error('SOURCE_ADAPTER_REQUEST_FAILED');
  }

  var body;
  try {
    body = JSON.parse(response.getContentText());
  } catch (ignored) {
    throw new Error('SOURCE_ADAPTER_RESPONSE_INVALID');
  }
  if (!body || body.schema !== 'H3_SOURCE_RESOLVE_RESPONSE_V1' ||
      body.ok !== true ||
      body.operation !== request.operation ||
      body.authority_channel !== request.authority_channel ||
      (request.expected_manifest_version_or_null !== null &&
       body.manifest_version !== request.expected_manifest_version_or_null) ||
      (request.expected_source_set_id_or_null !== null &&
       body.source_set_id !== request.expected_source_set_id_or_null)) {
    throw new Error('SOURCE_ADAPTER_RESPONSE_INVALID');
  }
  return body;
}
