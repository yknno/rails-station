require "jwt"

class SessionsController < ApplicationController
  # Bypass CSRF check for callback and backchannel logout
  protect_from_forgery except: [:create, :backchannel_logout]
  skip_before_action :load_active_session, only: [:create, :failure, :backchannel_logout]

  def create
    auth = request.env['omniauth.auth']

    raw_id_token = auth.credentials&.id_token
    if raw_id_token.blank?
      redirect_to root_path, alert: "Authentication failed: Missing ID token."
      return
    end

    # ID トークンの署名・iss/aud/nonce/exp は omniauth_openid_connect が
    # コールバック処理中に検証済み。ここでは sid / sub / exp を取り出すために
    # デコードするだけで、署名の再検証はしない。
    id_token_claims = JWT.decode(raw_id_token, nil, false).first

    # アクティブセッションレコードを作成します。
    active_session = ActiveSession.create_from_id_token!(raw_id_token, id_token_claims)

    session[:active_session_id] = active_session.id
    redirect_to root_path, notice: "Logged in successfully via OIDC!"
  rescue JWT::DecodeError => e
    Rails.logger.error "Failed to decode verified ID token: #{e.message}"
    redirect_to root_path, alert: "Authentication failed: Invalid ID token."
  end

  def destroy
    active_session = ActiveSession.find_by(id: session[:active_session_id]) if session[:active_session_id]
    raw_id_token = active_session&.raw_id_token
    
    # データベースのアクティブセッションレコードを削除
    active_session&.destroy
    reset_session
    
    if raw_id_token.present?
      oidc = Rails.configuration.x.oidc
      # 安全な URI 構築
      uri = URI(oidc.logout_endpoint)
      uri.query = URI.encode_www_form(
        id_token_hint: raw_id_token,
        post_logout_redirect_uri: oidc.post_logout_redirect_uri
      )
      redirect_to uri.to_s, allow_other_host: true, notice: "Logged out from RP. Redirecting to OP logout..."
    else
      redirect_to root_path, notice: "Logged out from RP."
    end
  end

  def backchannel_logout
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
      # Oidc::ValidationError / Oidc::ReplayAttackError are subclasses of JWT::DecodeError
      Rails.logger.error "Backchannel logout token verification failed: #{e.message}"
      head :bad_request
    end
  end

  def failure
    redirect_to root_path, alert: "Authentication failed: #{params[:message]}"
  end
end
