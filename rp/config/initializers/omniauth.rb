Rails.application.config.middleware.use OmniAuth::Builder do
  oidc = Rails.configuration.x.oidc
  
  # Parse internal URL to prevent fallback to https:443 when discovery: false
  internal_uri = URI(oidc.internal_url)

  provider :openid_connect, {
    name: :openid_connect,
    scope: [:openid, :profile, :email],
    response_type: :code,
    client_options: {
      identifier: oidc.client_id,
      secret: oidc.client_secret,
      redirect_uri: oidc.redirect_uri,
      authorization_endpoint: oidc.authorization_endpoint,
      token_endpoint: "#{oidc.internal_url}/oauth2/token",
      userinfo_endpoint: "#{oidc.internal_url}/userinfo",
      jwks_uri: oidc.jwks_uri,
      scheme: internal_uri.scheme,
      host: internal_uri.host,
      port: internal_uri.port
    },
    issuer: oidc.issuer,
    discovery: false
  }
end
