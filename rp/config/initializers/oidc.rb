hydra_public_host = ENV.fetch("HYDRA_PUBLIC_HOST") { "localhost" }

Rails.configuration.x.oidc.client_id = ENV.fetch("OIDC_CLIENT_ID") { "rp-client" }
Rails.configuration.x.oidc.client_secret = ENV.fetch("OIDC_CLIENT_SECRET") { "rp-client-secret" }

# Issuer must match exactly (Hydra is configured with http://localhost:4444/ URLS_SELF_ISSUER)
Rails.configuration.x.oidc.issuer = ENV.fetch("OIDC_ISSUER") { "http://localhost:4444/" }

# Internal URL for backchannel communication (container-to-container)
Rails.configuration.x.oidc.internal_url = ENV.fetch("OIDC_INTERNAL_URL") { "http://#{hydra_public_host}:4444" }
Rails.configuration.x.oidc.jwks_uri = "#{Rails.configuration.x.oidc.internal_url}/.well-known/jwks.json"

# Public URLs for browser redirection
Rails.configuration.x.oidc.public_url = ENV.fetch("OIDC_PUBLIC_URL") { "http://localhost:4444" }
Rails.configuration.x.oidc.authorization_endpoint = "#{Rails.configuration.x.oidc.public_url}/oauth2/auth"
Rails.configuration.x.oidc.logout_endpoint = "#{Rails.configuration.x.oidc.public_url}/oauth2/sessions/logout"

# RP URLs
rp_public_url = ENV.fetch("RP_PUBLIC_URL") { "http://localhost:3001" }
Rails.configuration.x.oidc.redirect_uri = "#{rp_public_url}/auth/openid_connect/callback"
Rails.configuration.x.oidc.post_logout_redirect_uri = "#{rp_public_url}/"
