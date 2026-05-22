# Ory Hydra Admin API (通常は内部通信用 4445 ポート) と通信し、各種 OAuth2/OIDC 要求を管理するサービス
# 参照: Ory Hydra Admin API Documentation
class OryHydraService
  class Error < StandardError; end

  def initialize
    # セキュリティ要件: Admin API へのアクセスは、外部へ公開されている Public API (4444 ポート) と分離され、
    # 本 OP バックエンドなどの閉じた内部ネットワークからのみルーティング可能にしなければならない
    @admin_url = ENV.fetch("HYDRA_ADMIN_URL") { "http://localhost:4445" }
    @conn = Faraday.new(url: @admin_url) do |faraday|
      faraday.request :json
      faraday.response :json
      faraday.adapter Faraday.default_adapter
    end
  end

  # Login requests (ログインチャレンジの取得、承諾、拒否)
  def get_login_request(challenge)
    raw = request(:get, "/admin/oauth2/auth/requests/login", params: { login_challenge: challenge })
    LoginRequest.new(raw)
  end

  # ユーザー認証に成功した場合に、ユーザーID (subject) を Hydra に送信して受託する
  def accept_login_request(challenge, subject)
    # Ory Hydra 仕様:
    # - remember: true にすることで、ブラウザの Hydra セッションクッキーにログイン情報を記録する
    # - remember_for: キャッシュの有効期間を秒単位で指定 (ここでは 3600 秒 = 1 時間)
    #   これにより、有効期間内であれば次回認証時に login_request.skip? == true となる
    payload = {
      subject: subject,
      remember: true,
      remember_for: 3600
    }
    request(:put, "/admin/oauth2/auth/requests/login/accept", params: { login_challenge: challenge }, body: payload)
  end

  # ユーザー認証に失敗、またはキャンセルされた場合に Hydra にエラーを通知する
  def reject_login_request(challenge, reason)
    payload = {
      error: "login_rejected",
      error_description: reason
    }
    request(:put, "/admin/oauth2/auth/requests/login/reject", params: { login_challenge: challenge }, body: payload)
  end

  # Consent requests (同意チャレンジの取得、承諾、拒否)
  def get_consent_request(challenge)
    request(:get, "/admin/oauth2/auth/requests/consent", params: { consent_challenge: challenge })
  end

  # ユーザーの同意が承諾された場合に、許可スコープと ID Token に追加するクレームを設定して Hydra に受託する
  def accept_consent_request(challenge, granted_scopes, granted_audience, user)
    id_token_claims = {}
    
    # 参照: OpenID Connect Core 1.0 Section 5.4 (Requesting Claims using Scope Values)
    # 各スコープに対応するクレームを ID Token に設定する。
    # - email スコープ: email と email_verified (OIDC Section 5.4 - Email Claims)
    if granted_scopes.include?("email")
      id_token_claims[:email] = user.email
      id_token_claims[:email_verified] = true
    end
    # - profile スコープ: name や preferred_username などの標準属性 (OIDC Section 5.4 - Profile Claims)
    if granted_scopes.include?("profile")
      id_token_claims[:name] = user.email.split('@').first.capitalize
      id_token_claims[:preferred_username] = user.email.split('@').first
    end

    # Ory Hydra 仕様:
    # - session.id_token 内のオブジェクトが、Hydra の生成する最終的な JWT ID Token のクレーム構造へ動的にマージされる
    payload = {
      grant_scope: granted_scopes,
      grant_access_token_audience: granted_audience,
      remember: true,
      remember_for: 3600,
      session: {
        id_token: id_token_claims
      }
    }
    request(:put, "/admin/oauth2/auth/requests/consent/accept", params: { consent_challenge: challenge }, body: payload)
  end

  # 同意が拒否された場合に Hydra に通知する
  def reject_consent_request(challenge, reason)
    payload = {
      error: "consent_rejected",
      error_description: reason
    }
    request(:put, "/admin/oauth2/auth/requests/consent/reject", params: { consent_challenge: challenge }, body: payload)
  end

  # Logout requests (ログアウトチャレンジの取得、承諾)
  def get_logout_request(challenge)
    request(:get, "/admin/oauth2/auth/requests/logout", params: { logout_challenge: challenge })
  end

  # ログアウト要求を Hydra に受託し、Hydra 側のセッション（およびセッションクッキー）をクリアさせる
  def accept_logout_request(challenge)
    request(:put, "/admin/oauth2/auth/requests/logout/accept", params: { logout_challenge: challenge }, body: {})
  end

  private

  def request(method, path, params: {}, body: nil)
    response = @conn.run_request(method, path, body, nil) do |req|
      req.params.update(params) if params.present?
    end

    unless response.success?
      raise Error, "Failed Hydra admin request to #{path}: #{response.status} #{response.body}"
    end

    response.body
  rescue Faraday::Error => e
    raise Error, "Faraday communication error with Hydra: #{e.message}"
  end
end
