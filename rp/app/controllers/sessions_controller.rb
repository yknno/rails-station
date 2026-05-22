require "jwt"

class SessionsController < ApplicationController
  # Bypass CSRF check for callback and backchannel logout
  protect_from_forgery except: [:create, :backchannel_logout]
  skip_before_action :load_active_session, only: [:create, :failure, :backchannel_logout]

  def create
    auth = request.env['omniauth.auth']
    active_session = Oidc::SessionManager.handle_callback(auth, Rails.configuration.x.oidc)

    session[:active_session_id] = active_session.id
    redirect_to root_path, notice: "Logged in successfully via OIDC!"
  rescue Oidc::TokenValidationError => e
    Rails.logger.error e.message
    redirect_to root_path, alert: "Authentication failed: Invalid ID token."
  end

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
