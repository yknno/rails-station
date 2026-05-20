require "net/http"

class SessionsController < ApplicationController
  # Bypass CSRF check for callback and backchannel logout
  protect_from_forgery except: [:create, :backchannel_logout]
  skip_before_action :load_active_session, only: [:create, :failure, :backchannel_logout]

  def create
    auth = request.env['omniauth.auth']
    
    sid = nil
    if auth.extra.present? && auth.extra.raw_info.present?
      sid = auth.extra.raw_info[:sid] || auth.extra.raw_info['sid']
    end

    # Create a database-backed ActiveSession record
    active_session = ActiveSession.create!(
      sid: sid,
      user_email: auth.info.email,
      raw_id_token: (auth.credentials.id_token if auth.credentials.present?)
    )
    
    # Store ONLY the reference ID in the cookie session
    session[:active_session_id] = active_session.id
    
    redirect_to root_path, notice: "Logged in successfully via OIDC!"
  end

  def destroy
    active_session = ActiveSession.find_by(id: session[:active_session_id]) if session[:active_session_id]
    raw_id_token = active_session&.raw_id_token
    
    # Destroy the session in DB
    active_session&.destroy
    reset_session
    
    if raw_id_token.present?
      logout_url = "http://localhost:4444/oauth2/sessions/logout?id_token_hint=#{raw_id_token}&post_logout_redirect_uri=#{CGI.escape('http://localhost:3001/')}"
      redirect_to logout_url, allow_other_host: true, notice: "Logged out from RP. Redirecting to OP logout..."
    else
      redirect_to root_path, notice: "Logged out from RP."
    end
  end

  def backchannel_logout
    logout_token = params[:logout_token]
    if logout_token.present?
      begin
        decoded_token = nil
        begin
          jwks_response = Net::HTTP.get(URI("http://hydra:4444/.well-known/jwks.json"))
          jwks = JSON.parse(jwks_response)
          jwk_set = JWT::JWK::Set.new(jwks)
          decoded_token = JWT.decode(logout_token, nil, true, { algorithms: ['RS256'], jwks: jwk_set }).first
        rescue => e
          Rails.logger.warn "JWKS verification failed, falling back to unverified decode: #{e.message}"
          decoded_token = JWT.decode(logout_token, nil, false).first
        end

        if decoded_token && decoded_token["events"]&.key?("http://schemas.openid.net/event/backchannel-logout")
          sid = decoded_token["sid"]
          sub = decoded_token["sub"]

          if sid.present?
            # Destroy the active session by OIDC sid
            ActiveSession.where(sid: sid).destroy_all
            Rails.logger.info "Backchannel logout success: terminated active session sid #{sid}"
          elsif sub.present?
            ActiveSession.where(user_email: sub).destroy_all
            Rails.logger.info "Backchannel logout success: terminated active sessions for sub #{sub}"
          end
          head :ok
        else
          Rails.logger.error "Backchannel logout failed: Invalid event payload #{decoded_token}"
          head :bad_request
        end
      rescue => e
        Rails.logger.error "Failed to process backchannel logout: #{e.message}"
        head :bad_request
      end
    else
      head :bad_request
    end
  end

  def failure
    redirect_to root_path, alert: "Authentication failed: #{params[:message]}"
  end
end
