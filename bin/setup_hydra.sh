#!/bin/bash
set -e

ADMIN_URL=${HYDRA_ADMIN_URL:-"http://localhost:4445"}

echo "Waiting for Ory Hydra Admin API at ${ADMIN_URL} to be ready..."
until curl -s "${ADMIN_URL}/health/ready" > /dev/null; do
  sleep 1
done
echo "Ory Hydra Admin API is ready."

echo "Registering/updating OIDC client: rp-client via REST API..."
curl -s -X PUT \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "rp-client",
    "client_secret": "rp-client-secret",
    "grant_types": ["authorization_code", "refresh_token"],
    "response_types": ["code"],
    "scope": "openid profile email offline_access",
    "redirect_uris": ["http://localhost:3001/auth/openid_connect/callback"],
    "post_logout_redirect_uris": ["http://localhost:3001/"],
    "backchannel_logout_uri": "http://rp:3001/auth/backchannel_logout",
    "backchannel_logout_session_required": true
  }' \
  "${ADMIN_URL}/admin/clients/rp-client" > /dev/null

echo "Ory Hydra client setup complete!"
