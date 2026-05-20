Rails.application.config.middleware.use OmniAuth::Builder do
  provider :openid_connect, {
    name: :openid_connect,
    scope: [:openid, :profile, :email],
    response_type: :code,
    client_options: {
      identifier: ENV.fetch("OIDC_CLIENT_ID") { "rp-client" },
      secret: ENV.fetch("OIDC_CLIENT_SECRET") { "rp-client-secret" },
      redirect_uri: "http://localhost:3001/auth/openid_connect/callback",
      authorization_endpoint: "http://localhost:4444/oauth2/auth",
      token_endpoint: "http://hydra:4444/oauth2/token",
      userinfo_endpoint: "http://hydra:4444/userinfo",
      jwks_uri: "http://hydra:4444/.well-known/jwks.json"
    },
    issuer: "http://localhost:4444/",
    discovery: false
  }
end
