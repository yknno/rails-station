module Oidc
  # OIDC の認証・ログアウト用セッション管理を行うサービス
  class SessionManager
    class << self
      # コールバック受信時のセッション作成処理
      # 参照: OpenID Connect Core 1.0 Section 3.1.2.5 (Successful Authentication Response)
      # - `omniauth-openid-connect` が事前に Token Endpoint から取得・検証した結果を受け取る
      # 
      # 仕様との乖離 / 改善点:
      # - `JWT.decode(..., nil, false)` を使用して署名検証を行わずに ID Token をデコードし、Claims を抽出している。
      #   これは `omniauth_openid_connect` ライブラリ内部で既に署名・検証（iss, aud, exp, nonce等）がパスしたものである前提となっている。
      #   しかし、二重防壁としてこのサービス層でも `Oidc::TokenDecoder` などを通して OP の JWKS で署名再検証を行うとより堅牢になる。
      def handle_callback(auth, oidc_config)
        raw_id_token = auth.credentials&.id_token
        if raw_id_token.blank?
          raise TokenValidationError, "Authentication failed: Missing ID token."
        end

        id_token_claims = JWT.decode(raw_id_token, nil, false).first
        ActiveSession.create_from_id_token!(raw_id_token, id_token_claims)
      rescue JWT::DecodeError => e
        raise TokenValidationError, "Failed to decode verified ID token: #{e.message}"
      end

      # OP側の End Session Endpoint (ログアウトエンドポイント) 用のURLを生成する
      # 参照: OpenID Connect RP-Initiated Logout 1.0 Section 2 (RP-Initiated Logout Endpoint)
      # - パラメータ `id_token_hint`: ログアウトさせるユーザーの過去の ID Token（必須または推奨）。OP はこれを使用してどのセッションをログアウトさせるか特定する。
      # - パラメータ `post_logout_redirect_uri`: OP ログアウト完了後に RP にリダイレクトバックさせる宛先 URL。
      def logout_url(active_session, oidc_config)
        raw_id_token = active_session&.raw_id_token
        return nil if raw_id_token.blank?

        uri = URI(oidc_config.logout_endpoint)
        uri.query = URI.encode_www_form(
          id_token_hint: raw_id_token,
          post_logout_redirect_uri: oidc_config.post_logout_redirect_uri
        )
        uri.to_s
      end
    end
  end
end
