#!/bin/sh
set -e

ADMIN_URL=${HYDRA_ADMIN_URL:-"http://localhost:4445"}

echo "Waiting for Ory Hydra Admin API at ${ADMIN_URL} to be ready..."
until curl -s "${ADMIN_URL}/health/ready" > /dev/null; do
  sleep 1
done
echo "Ory Hydra Admin API is ready."

CLIENT_PAYLOAD='{
  "client_id": "rp-client",
  "client_secret": "rp-client-secret",
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "scope": "openid profile email offline_access",
  "redirect_uris": ["http://localhost:3001/auth/openid_connect/callback"],
  "post_logout_redirect_uris": ["http://localhost:3001/"],
  "backchannel_logout_uri": "http://rp:3001/auth/backchannel_logout",
  "backchannel_logout_session_required": true
}'

echo "Checking if OIDC client 'rp-client' already exists..."
STATUS_CODE=$(curl -o /dev/null -s -w "%{http_code}" "${ADMIN_URL}/admin/clients/rp-client")

if [ "$STATUS_CODE" -eq 200 ]; then
  echo "Client 'rp-client' exists. Updating it via PUT..."
  curl -f -sS -X PUT \
    -H "Content-Type: application/json" \
    -d "$CLIENT_PAYLOAD" \
    "${ADMIN_URL}/admin/clients/rp-client"
elif [ "$STATUS_CODE" -eq 404 ]; then
  echo "Client 'rp-client' does not exist. Creating it via POST..."
  curl -f -sS -X POST \
    -H "Content-Type: application/json" \
    -d "$CLIENT_PAYLOAD" \
    "${ADMIN_URL}/admin/clients"
else
  echo "Error: Unexpected status code $STATUS_CODE when checking client existence." >&2
  exit 1
fi

echo ""
echo "Ory Hydra client setup complete!"
