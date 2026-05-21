module Oidc
  class TokenDecoder
    class << self
      def decode_and_verify(token, jwks_uri, options = {})
        begin
          header = JWT.decode(token, nil, false).last
          kid = header ? header["kid"] : nil
        rescue => e
          Rails.logger.warn "Failed to parse JWT header: #{e.message}"
          kid = nil
        end

        set = Oidc::JwksProvider.jwk_set(jwks_uri)

        # トークンの kid がキャッシュされた JWKS 内に見つからない場合、キャッシュをクリアして再取得を試みる（レートリミットあり）
        if kid.present? && !Oidc::JwksProvider.kid_in_set?(kid, set)
          Rails.logger.info "kid #{kid} not found in cached JWKS. Forcing rate-limited refresh..."
          set = Oidc::JwksProvider.jwk_set(jwks_uri, force: true)
        end

        if set.nil?
          raise Oidc::JwksUnavailableError, "JWKS not available from provider"
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
end
