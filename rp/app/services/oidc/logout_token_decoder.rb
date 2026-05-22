module Oidc
  # OP から送られた Logout Token のデコードと仕様準拠検証を行うサービス
  # 参照: OpenID Connect Back-Channel Logout 1.0 Section 2.4 (Logout Token Validation)
  class LogoutTokenDecoder
    class << self
      def decode(token, oidc)
        # TokenDecoder を介して JWKS を用い署名と iat 期限を検証 (Section 2.4, Item 1 & Item 4の一部)
        claims = Oidc::TokenDecoder.decode_and_verify(token, oidc.jwks_uri)

        # 1. issuer (iss) の検証 (Section 2.4, Item 2)
        # Logout Token の iss 値は、OP の Issuer 識別子と完全に一致しなければならない
        if claims['iss'] != oidc.issuer
          raise TokenValidationError, "Logout token validation failed: issuer mismatch. Expected #{oidc.issuer}, got #{claims['iss']}"
        end

        # 2. audience (aud) の検証 (Section 2.4, Item 3)
        # Logout Token の aud 値は、RP の Client ID と一致しなければならない（配列形式のターゲットも考慮）
        if claims['aud'] != oidc.client_id && !Array(claims['aud']).include?(oidc.client_id)
          raise TokenValidationError, "Logout token validation failed: audience mismatch. Expected #{oidc.client_id}, got #{claims['aud']}"
        end

        # 2.5. expiration (exp) の検証 (Section 2.4, Item 10)
        # Back-channel Logout においては exp クレームは必須要件である
        if claims['exp'].blank?
          raise TokenValidationError, "Logout token validation failed: missing exp claim"
        end

        # 3. events クレームの検証 (Section 2.4, Item 5)
        # "http://schemas.openid.net/event/backchannel-logout" キーを持ち、値は空の JSON オブジェクト {} でなければならない
        events = claims['events']
        unless events.is_a?(Hash) &&
               events.key?("http://schemas.openid.net/event/backchannel-logout") &&
               events["http://schemas.openid.net/event/backchannel-logout"].is_a?(Hash) &&
               events["http://schemas.openid.net/event/backchannel-logout"].empty?
          raise TokenValidationError, "Logout token validation failed: invalid events claim structure"
        end

        # 4. nonce が含まれていないことの検証 (Section 2.4, Item 6)
        # ログアウトにおいて nonce があると、過去のログイン時の nonce が使い回された場合に
        # セキュリティ攻撃の温床となるため、Logout Token 内での nonce の存在は禁止されている (MUST NOT contain a nonce claim)
        if claims.key?('nonce')
          raise TokenValidationError, "Logout token validation failed: contains prohibited nonce claim"
        end

        # 5. iat が現在時刻に近いことの検証 (Section 2.4, Item 4)
        # iat (Issued At) 値を検証し、現在時刻から外れすぎている古いトークンは破棄する（ここでは猶予期間として±5分を許容）
        iat = claims['iat'].to_i
        now = Time.now.to_i
        if iat.zero? || (iat - now).abs > 5.minutes.to_i
          raise TokenValidationError, "Logout token validation failed: iat is not close to current time. iat: #{iat}, now: #{now}"
        end

        # 6. sub または sid のいずれかが存在することの検証 (Section 2.4, Item 8)
        # ログアウト対象ユーザーを特定するため、sub (Subject) または sid (Session ID) の少なくとも一方が存在しなければならない (MUST contain a sub or sid or both)
        if claims['sub'].blank? && claims['sid'].blank?
          raise TokenValidationError, "Logout token validation failed: both sub and sid claims are missing"
        end

        # 7. jti が存在することの検証 (Section 2.4, Item 9)
        # リプレイ攻撃を防止するため、一意の識別子 jti (JWT ID) が必須とされる (MUST contain a jti claim)
        if claims['jti'].blank?
          raise TokenValidationError, "Logout token validation failed: missing jti claim"
        end

        claims
      end
    end
  end
end
