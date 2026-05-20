class OidcService
  class JwksUnavailableError < StandardError; end

  class << self
    def fetch_jwks(force: false)
      if force
        # Rate limit forcing refresh to prevent DoS (max once every 1 minute)
        last_fetched = Rails.cache.read("oidc_jwks_fetched_at")
        if last_fetched.nil? || last_fetched < 1.minute.ago
          Rails.cache.delete("oidc_jwks")
          Rails.cache.write("oidc_jwks_fetched_at", Time.current)
        else
          return Rails.cache.read("oidc_jwks")
        end
      end

      Rails.cache.fetch("oidc_jwks", expires_in: 24.hours) do
        Rails.cache.write("oidc_jwks_fetched_at", Time.current)
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

    def jwk_set(force: false)
      jwks = fetch_jwks(force: force)
      jwks ? JWT::JWK::Set.new(jwks) : nil
    end

    def decode_and_verify(token, options = {})
      # Extract kid from token header without verification
      begin
        header = JWT.decode(token, nil, false).last
        kid = header ? header["kid"] : nil
      rescue => e
        Rails.logger.warn "Failed to parse JWT header: #{e.message}"
        kid = nil
      end

      set = jwk_set

      # If the kid is not present in the current cached JWKS, clear cache and re-fetch (with rate limit)
      if kid.present? && !kid_in_set?(kid, set)
        Rails.logger.info "kid #{kid} not found in cached JWKS. Forcing rate-limited refresh..."
        set = jwk_set(force: true)
      end

      if set.nil?
        raise JwksUnavailableError, "JWKS not available from provider"
      end

      default_options = {
        algorithms: ['RS256'],
        jwks: set,
        verify_iat: true
      }

      JWT.decode(token, nil, true, default_options.merge(options)).first
    end

    private

    def kid_in_set?(kid, set)
      jwks = fetch_jwks
      return false if jwks.blank? || jwks["keys"].blank?
      jwks["keys"].any? { |key| key["kid"] == kid }
    end
  end
end
