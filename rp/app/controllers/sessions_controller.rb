require "net/http"

class SessionsController < ApplicationController
  # Bypass CSRF check for callback and backchannel logout
  protect_from_forgery except: [:create, :backchannel_logout]
  skip_before_action :check_revoked_session, only: [:create, :failure, :backchannel_logout]

  def create
    auth = request.env['omniauth.auth']
    
    # Store only essential attributes in session to keep cookie size small (under 4KB limit)
    session[:user_email] = auth.info.email
    session[:raw_id_token] = auth.credentials.id_token if auth.credentials.present?
    if auth.extra.present? && auth.extra.raw_info.present?
      session[:sid] = auth.extra.raw_info[:sid] || auth.extra.raw_info['sid']
    end
    
    redirect_to root_path, notice: "Logged in successfully via OIDC!"
  end

  def destroy
    raw_id_token = session[:raw_id_token]
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
            RevokedSession.create!(sid: sid)
            Rails.logger.info "Backchannel logout success: revoked session sid #{sid}"
          elsif sub.present?
            RevokedSession.create!(sid: "sub:#{sub}")
            Rails.logger.info "Backchannel logout success: revoked session for sub #{sub}"
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
