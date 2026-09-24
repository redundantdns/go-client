#!/usr/bin/env bash
# Records the httptest fixtures in rdnstest/fixtures from a RedundantDNS
# deployment running in e2e mode (any e-mail, login code 123456, the "fake"
# provider available). It creates a throwaway zone, connection and alert
# channel, captures every answer, then deletes them.
#
#   RDNS_BASE_URL=http://192.168.16.40:8080 ./scripts/record-fixtures.sh
#
# Secrets (tokens, webhook secrets) and client IPs are replaced by
# placeholders before the files are written. Synthetic fixtures (states the
# lab cannot produce on demand, such as a firing alert) are named
# synthetic_*.json and are not touched by this script.
set -euo pipefail

base="${RDNS_BASE_URL:?set RDNS_BASE_URL}"
out="$(cd "$(dirname "$0")/.." && pwd)/rdnstest/fixtures"
email="fixtures-$(date +%s)@example.com"
zone_name="fixtures-$(date +%s).example.com"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$out"

# save <name> <status> <file>: writes testdata/fixtures/<name>.json with the
# status on the first line of a small envelope.
save() {
  local name="$1" status="$2" file="$3"
  jq --argjson status "$status" '{status: $status, body: .}' "$file" \
    | sed -E 's/rdns_[A-Za-z0-9_]+/rdns_REDACTED/g; s/whsec_[A-Za-z0-9]+/whsec_REDACTED/g; s/"ip": "[^"]*"/"ip": "198.51.100.7"/g' \
    >"$out/$name.json"
}

# call <name> <method> <path> [body]: runs a request with the PAT and saves
# the JSON answer.
call() {
  local name="$1" method="$2" path="$3" body="${4:-}"
  local args=(-s -o "$work/body" -w '%{http_code}' -X "$method" -H "Authorization: Bearer $token")
  if [[ -n "$body" ]]; then
    args+=(-H 'Content-Type: application/json' -d "$body")
  fi
  local status
  status="$(curl "${args[@]}" "$base$path")"
  save "$name" "$status" "$work/body"
  cp "$work/body" "$work/$name"
}

curl -s -X POST "$base/auth/code" -H 'Content-Type: application/json' -d "{\"email\":\"$email\"}" >/dev/null
curl -s -c "$work/cookies" -o "$work/verify" -X POST "$base/auth/verify" -H 'Content-Type: application/json' \
  -d "{\"email\":\"$email\",\"code\":\"123456\"}"
save auth_verify 200 "$work/verify"
versions="$(curl -s "$base/v1/legal/versions")"
curl -s -b "$work/cookies" -o "$work/legal" -X POST "$base/v1/me/legal/accept" -H 'Content-Type: application/json' \
  -d "$(jq -c '{termsVersion: .terms, privacyVersion: .privacy}' <<<"$versions")"
save legal_accept 200 "$work/legal"
curl -s -b "$work/cookies" -o "$work/token" -X POST "$base/v1/tokens" -H 'Content-Type: application/json' \
  -d '{"name":"fixtures","scopes":["zones:read","zones:write","connections:read","connections:write"],"expiresInDays":1}'
token="$(jq -r .token "$work/token")"
token_id="$(jq -r .record.tokenId "$work/token")"
save token_create 201 "$work/token"

call me GET /v1/me
call providers GET /v1/providers
call connection_create POST /v1/connections '{"provider":"fake","label":"Fixture fake","accessLevel":"zone_admin","credentials":{"token":"fixture-token"}}'
connection_id="$(jq -r .connection.connectionId "$work/connection_create")"
call connection_list GET /v1/connections
call connection_test POST "/v1/connections/$connection_id/test"
call zone_create POST /v1/zones "{\"name\":\"$zone_name\"}"
zone_id="$(jq -r .zoneId "$work/zone_create")"
call attachment_create POST "/v1/zones/$zone_id/attachments" "{\"connectionId\":\"$connection_id\"}"
attachment_id="$(jq -r .attachment.attachmentId "$work/attachment_create")"
call record_upsert PUT "/v1/zones/$zone_id/records" '{"name":"www","type":"A","ttl":300,"values":["192.0.2.10"]}'
call reconcile POST "/v1/zones/$zone_id/reconcile" '{}'
call verify POST "/v1/zones/$zone_id/verify" '{}'
sleep 3
call zone_get GET "/v1/zones/$zone_id"
call zone_list GET /v1/zones
call record_list GET "/v1/zones/$zone_id/records"
call zone_status GET "/v1/zones/$zone_id/status"
call delegation_check POST "/v1/zones/$zone_id/delegation/check"
call journal GET "/v1/zones/$zone_id/journal"
curl -s -o "$work/export" -H "Authorization: Bearer $token" "$base/v1/zones/$zone_id/export"
cp "$work/export" "$out/zone_export.txt"
call adopt POST "/v1/zones/$zone_id/attachments/$attachment_id/adopt"
call record_delete DELETE "/v1/zones/$zone_id/records?name=www&type=A"
call alert_rules GET /v1/alerts/rules
call alert_channel_create POST /v1/alerts/channels '{"kind":"webhook","label":"Fixture hook","target":"https://hooks.example.com/rdns"}'
channel_id="$(jq -r .channel.channelId "$work/alert_channel_create")"
call alert_channels GET /v1/alerts/channels
call alert_events GET "/v1/alerts/events?limit=10"
call alert_resolve_missing POST /v1/alerts/events/evt-missing/resolve
call zone_missing GET /v1/zones/zone-missing
call audit GET "/v1/audit?zoneId=$zone_id"

# Managed terms and subdomain redundancy (G4b); skipped on deployments
# that do not serve managedTerms yet. The run's organization is new, so
# the terms are not accepted when the status and the 428 are captured.
if jq -e '.managedTerms' <<<"$versions" >/dev/null; then
  managed_version="$(jq -r .managedTerms <<<"$versions")"
  printf '%s' "$versions" >"$work/versions"
  save legal_versions 200 "$work/versions"
  call legal_managed_status GET /v1/legal/managed
  call managed_terms_required POST /v1/connections '{"provider":"fake","mode":"managed","label":"Fixture managed"}'
  call legal_managed_accept POST /v1/legal/managed/accept "{\"version\":\"$managed_version\"}"
  call zone_create_child POST /v1/zones "{\"name\":\"api.$zone_name\",\"parentDelegation\":true}"
  child_id="$(jq -r .zoneId "$work/zone_create_child")"
  curl -s -X DELETE -H "Authorization: Bearer $token" "$base/v1/zones/$child_id" >/dev/null
fi

# Clean up everything this run created.
call alert_channel_delete DELETE "/v1/alerts/channels/$channel_id"
call attachment_delete DELETE "/v1/zones/$zone_id/attachments/$attachment_id?deleteRemote=true&confirmName=$zone_name"
call zone_delete DELETE "/v1/zones/$zone_id"
call connection_delete DELETE "/v1/connections/$connection_id"
curl -s -b "$work/cookies" -X DELETE "$base/v1/tokens/$token_id" >/dev/null
echo "fixtures written to $out"
