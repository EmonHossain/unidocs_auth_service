#!/bin/bash
set -eu
for value in "$ELASTIC_PASSWORD" "$KIBANA_SYSTEM_PASSWORD" "$TELEMETRY_WRITER_PASSWORD"; do
  [[ "$value" =~ ^[A-Za-z0-9_-]+$ ]] || { echo 'Telemetry credentials must contain only letters, digits, underscores or hyphens.' >&2; exit 1; }
done
api() {
  curl --fail --silent --show-error --user "elastic:$ELASTIC_PASSWORD" \
    -H 'Content-Type: application/json' -X "${2:-POST}" "http://elasticsearch:9200/$1" --data-binary @- > /dev/null
}
printf '{"password":"%s"}' "$KIBANA_SYSTEM_PASSWORD" | api _security/user/kibana_system/_password
printf '%s' '{"cluster":["monitor","manage_index_templates","manage_ilm"],"indices":[{"names":["filebeat-*","logs-apm*","traces-apm*","metrics-apm*"],"privileges":["auto_configure","create_index","create_doc","write","read","view_index_metadata","manage"]},{"names":[".apm-agent-configuration"],"privileges":["read"],"allow_restricted_indices":true}]}' | api _security/role/admin
printf '{"password":"%s","roles":["superuser"]}' "$TELEMETRY_WRITER_PASSWORD" | api _security/user/admin
# Filebeat-owned data streams use a bounded local lifecycle; APM uses its integration defaults.
printf '%s' '{"policy":{"phases":{"hot":{"actions":{"rollover":{"max_age":"1d","max_primary_shard_size":"1gb"}}},"delete":{"min_age":"7d","actions":{"delete":{}}}}}}' | api _ilm/policy/unidocs-auth-logs PUT
printf '%s\n' 'Local telemetry identities and log lifecycle are ready.'
