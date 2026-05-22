module Oidc
  class LogoutTokenDecoder
    class << self
      def decode(token, oidc)
        claims = Oidc::TokenDecoder.decode_and_verify(token, oidc.jwks_uri)

        # 1. issuer (iss) の検証
        if claims['iss'] != oidc.issuer
          raise TokenValidationError, "Logout token validation failed: issuer mismatch. Expected #{oidc.issuer}, got #{claims['iss']}"
        end

        # 2. audience (aud) の検証
        if claims['aud'] != oidc.client_id && !Array(claims['aud']).include?(oidc.client_id)
          raise TokenValidationError, "Logout token validation failed: audience mismatch. Expected #{oidc.client_id}, got #{claims['aud']}"
        end

        # 2.5. expiration (exp) の検証 (exp is required)
        if claims['exp'].blank?
          raise TokenValidationError, "Logout token validation failed: missing exp claim"
        end

        # 3. events の検証
        events = claims['events']
        unless events.is_a?(Hash) &&
               events.key?("http://schemas.openid.net/event/backchannel-logout") &&
               events["http://schemas.openid.net/event/backchannel-logout"].is_a?(Hash)
          raise TokenValidationError, "Logout token validation failed: invalid events claim structure"
        end

        # 4. nonce が含まれていないことの検証
        if claims.key?('nonce')
          raise TokenValidationError, "Logout token validation failed: contains prohibited nonce claim"
        end

        # 5. iat が現在時刻に近いことの検証（古いトークンの再利用を防ぐために±5分以内とする）
        iat = claims['iat'].to_i
        now = Time.now.to_i
        if iat.zero? || (iat - now).abs > 5.minutes.to_i
          raise TokenValidationError, "Logout token validation failed: iat is not close to current time. iat: #{iat}, now: #{now}"
        end

        # 6. sub または sid のいずれかが存在することの検証
        if claims['sub'].blank? && claims['sid'].blank?
          raise TokenValidationError, "Logout token validation failed: both sub and sid claims are missing"
        end

        # 7. jti が存在することの検証（jti is required for backchannel logout token replay prevention）
        if claims['jti'].blank?
          raise TokenValidationError, "Logout token validation failed: missing jti claim"
        end

        claims
      end
    end
  end
end
