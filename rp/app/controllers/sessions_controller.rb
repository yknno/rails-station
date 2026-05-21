require "net/http"
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

    oidc = Rails.configuration.x.oidc

    # Oidc::IdTokenDecoder を使用して ID トークンの署名と標準クレームを検証します。
    begin
      decoded_payload = Oidc::IdTokenDecoder.decode(raw_id_token, oidc)
    rescue Oidc::JwksUnavailableError => e
      redirect_to root_path, alert: "Authentication failed: Identity provider keys are currently unavailable. Please try again later."
      return
    rescue JWT::DecodeError => e
      redirect_to root_path, alert: "ID Token verification failed: #{e.message}"
      return
    end

    # アクティブセッションレコードを作成します。
    active_session = ActiveSession.create_from_id_token!(raw_id_token, decoded_payload)
    
    session[:active_session_id] = active_session.id
    redirect_to root_path, notice: "Logged in successfully via OIDC!"
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
