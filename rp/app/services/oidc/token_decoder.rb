module Oidc
  # JWTトークンのデコードおよび署名と有効期限の検証を行う共通サービス
  class TokenDecoder
    class << self
      # トークンをデコードし、署名とJWTの標準クレームを検証する
      # 参照:
      # - OpenID Connect Core 1.0 Section 3.1.3.7 (ID Token Validation)
      # - RFC 7519 (JSON Web Token - JWT) Section 7.2 (Validating a JWT)
      #
      # 仕様対応の詳細:
      # - JWT のヘッダーから `kid` (Key ID) を抽出し、OP が公開している JWKS 内の特定の鍵とマッピングする (RFC 7517 Section 4.5)
      # - JWKS 内にトークンの `kid` が見つからない場合は、鍵がローテーションされた可能性があるため、
      #   キャッシュを破棄して JWKS の最新情報を再取得する（鍵ローテーションへの動的対応）
      # - 署名アルゴリズムは OIDC のデフォルトである `RS256` に限定 (OIDC Core 1.0 Section 3.1.3.7 Item 7)
      # - `verify_iat: true` により、JWT の発行日時 `iat` の検証を有効化 (OIDC Core 1.0 Section 3.1.3.7 Item 11)
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
