require "jwt"
require "net/http"

class ActiveSession < ApplicationRecord
  def expired?
    expires_at.present? && expires_at < Time.current
  end

  def claims
    return {} if raw_id_token.blank?
    @claims ||= decode_and_verify_id_token
  end

  def user_email
    claims["email"]
  end

  private

  def decode_and_verify_id_token
    oidc = Rails.configuration.x.oidc
    OidcService.decode_and_verify(raw_id_token, {
      aud: oidc.client_id,
      verify_aud: true,
      iss: oidc.issuer,
      verify_iss: true
    })
  rescue => e
    Rails.logger.error "ActiveSession ID token verification failed: #{e.message}"
    {}
  end
end
