require "jwt"

# OIDC 認証コールバックおよびログアウト要求（RP始動ログアウト、バックチャネルログアウト）を処理するコントローラ
class SessionsController < ApplicationController
  # OIDC / OAuth 2.0 に準拠したエンドポイント用設定:
  # - OIDC 認証コールバック (POST/GET) および Back-channel Logout (POST) は CSRF 対策をバイパスする
  #   (Back-channel Logout 1.0 Section 2.5: OP が直接 RP のエンドポイントに HTTP POST を送信するため)
  protect_from_forgery except: [:create, :backchannel_logout]
  skip_before_action :load_active_session, only: [:create, :failure, :backchannel_logout]

  # OIDC 認証コールバックハンドラ
  # 参照: OpenID Connect Core 1.0 Section 3.1.2.5 (Successful Authentication Response)
  # - ブラウザから認可コード（code）や状態（state）を受信
  # - OmniAuth ミドルウェアが裏で Token Endpoint にリクエストを送り (Section 3.1.3.1)、ID Token と Access Token を取得 (Section 3.1.3.3)
  # - 取得された Claims や Token 情報が `request.env['omniauth.auth']` に格納される
  def create
    auth = request.env['omniauth.auth']
    active_session = Oidc::SessionManager.handle_callback(auth, Rails.configuration.x.oidc)

    session[:active_session_id] = active_session.id
    redirect_to root_path, notice: "Logged in successfully via OIDC!"
  rescue Oidc::TokenValidationError => e
    Rails.logger.error e.message
    redirect_to root_path, alert: "Authentication failed: Invalid ID token."
  end

  # RP-Initiated Logout (RP始動ログアウト)
  # 参照: OpenID Connect RP-Initiated Logout 1.0 Section 2 (RP-Initiated Logout Endpoint)
  # - RP 側のセッション（ローカルのクッキーおよびセッションレコード）を破棄
  # - OP のログアウトエンドポイントへ `id_token_hint` や `post_logout_redirect_uri` を付与してリダイレクト
  def destroy
    active_session = ActiveSession.find_by(id: session[:active_session_id]) if session[:active_session_id]
    logout_url = Oidc::SessionManager.logout_url(active_session, Rails.configuration.x.oidc)
    
    # データベースのアクティブセッションレコードを削除
    active_session&.destroy
    reset_session
    
    if logout_url.present?
      redirect_to logout_url, allow_other_host: true, notice: "Logged out from RP. Redirecting to OP logout..."
    else
      redirect_to root_path, notice: "Logged out from RP."
    end
  end

  # Back-channel Logout の受信エンドポイント
  # 参照: OpenID Connect Back-Channel Logout 1.0 Section 2.5 (Back-Channel Logout Request)
  # - OP が直接バックチャネル (HTTP POST) で `logout_token` パラメータを送信
  # - セキュリティ上の必須要件 (Section 2.5): レスポンスに Cache-Control: no-store / Pragma: no-cache を設定
  # - レスポンスステータス (Section 2.6): 検証成功時は HTTP 200 OK、エラー時は HTTP 400 Bad Request、一時的なシステム障害は HTTP 503
  def backchannel_logout
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"

    logout_token = params[:logout_token]
    if logout_token.blank?
      head :bad_request
      return
    end

    oidc = Rails.configuration.x.oidc

    begin
      Oidc::BackchannelLogoutProcessor.process(logout_token, oidc)
      head :ok
    rescue Oidc::JwksUnavailableError => e
      Rails.logger.error "Backchannel logout failed due to JWKS unavailability: #{e.message}"
      head :service_unavailable
    rescue JWT::DecodeError => e
      # Oidc::TokenValidationError / Oidc::ReplayAttackError are subclasses of JWT::DecodeError
      Rails.logger.error "Backchannel logout token verification failed: #{e.message}"
      head :bad_request
    end
  end

  def failure
    redirect_to root_path, alert: "Authentication failed: #{params[:message]}"
  end
end
