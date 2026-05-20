class OidcService
  class << self
    def fetch_jwks
      Rails.cache.fetch("oidc_jwks", expires_in: 24.hours) do
        oidc = Rails.configuration.x.oidc
        begin
          jwks_response = Net::HTTP.get(URI(oidc.jwks_uri))
          JSON.parse(jwks_response)
        rescue => e
          Rails.logger.error "Failed to fetch JWKS from #{oidc.jwks_uri}: #{e.message}"
          nil
        end
      end
    end

    def jwk_set
      jwks = fetch_jwks
      jwks ? JWT::JWK::Set.new(jwks) : nil
    end

    def decode_and_verify(token, options = {})
      set = jwk_set
      if set.nil?
        raise JWT::DecodeError, "JWKS not available"
      end

      default_options = {
        algorithms: ['RS256'],
        jwks: set,
        verify_iat: true
      }

      JWT.decode(token, nil, true, default_options.merge(options)).first
    end
  end
end
