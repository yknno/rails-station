require "jwt"
require "net/http"

class ActiveSession < ApplicationRecord
  def expired?
    expires_at.present? && expires_at < Time.current
  end

  def claims
    return {} if raw_id_token.blank?

    jwks = Rails.cache.fetch("oidc_jwks", expires_in: 24.hours) do
      oidc = Rails.configuration.x.oidc
      begin
        jwks_response = Net::HTTP.get(URI(oidc.jwks_uri))
        JSON.parse(jwks_response)
      rescue => e
        Rails.logger.error "Failed to fetch JWKS for dynamic token verification: #{e.message}"
        nil
      end
    end

    return {} if jwks.blank?

    begin
      jwk_set = JWT::JWK::Set.new(jwks)
      oidc = Rails.configuration.x.oidc

      JWT.decode(raw_id_token, nil, true, {
        algorithms: ['RS256'],
        jwks: jwk_set,
        aud: oidc.client_id,
        verify_aud: true,
        iss: oidc.issuer,
        verify_iss: true
      }).first
    rescue JWT::DecodeError => e
      Rails.logger.error "ActiveSession ID token verification failed: #{e.message}"
      {}
    end
  end

  def user_email
    claims["email"]
  end
end
