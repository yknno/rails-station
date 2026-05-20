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

    # Fetch JWKS and verify the ID token signature & standard claims
    begin
      jwks_response = Net::HTTP.get(URI(oidc.jwks_uri))
      jwks = JSON.parse(jwks_response)
      jwk_set = JWT::JWK::Set.new(jwks)
      
      decoded_payload = JWT.decode(raw_id_token, nil, true, {
        algorithms: ['RS256'],
        jwks: jwk_set,
        aud: oidc.client_id,
        verify_aud: true,
        iss: oidc.issuer,
        verify_iss: true,
        verify_iat: true
      }).first
    rescue JWT::DecodeError => e
      redirect_to root_path, alert: "ID Token verification failed: #{e.message}"
      return
    end

    # Extract expiration and OIDC session identifier (sid)
    expires_at = Time.at(decoded_payload['exp']) if decoded_payload['exp'].present?
    expires_at ||= 1.hour.from_now
    
    sid = decoded_payload['sid']
    sub = decoded_payload['sub']

    # Create active session record
    active_session = ActiveSession.create!(
      sid: sid,
      sub: sub,
      raw_id_token: raw_id_token,
      expires_at: expires_at
    )
    
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
      oidc = Rails.configuration.x.oidc
      # Safe URI construction
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
      # Fetch JWKS and decode with signature verification
      jwks_response = Net::HTTP.get(URI(oidc.jwks_uri))
      jwks = JSON.parse(jwks_response)
      jwk_set = JWT::JWK::Set.new(jwks)
      
      decoded_token = JWT.decode(logout_token, nil, true, {
        algorithms: ['RS256'],
        jwks: jwk_set,
        verify_iat: true
      }).first

      # Replay prevention using jti
      jti = decoded_token["jti"]
      if jti.blank?
        Rails.logger.error "Backchannel logout validation failed: missing jti claim"
        head :bad_request
        return
      end

      if Rails.cache.read("logout_jti:#{jti}")
        Rails.logger.error "Backchannel logout validation failed: replayed jti #{jti}"
        head :bad_request
        return
      end

      # Perform OIDC Back-Channel Logout 1.0 claims validation
      if validate_logout_token(decoded_token)
        # Write to cache to prevent replay
        Rails.cache.write("logout_jti:#{jti}", true, expires_in: 10.minutes)

        sid = decoded_token["sid"]
        sub = decoded_token["sub"]

        if sid.present?
          ActiveSession.where(sid: sid).destroy_all
          Rails.logger.info "Backchannel logout success: terminated active session sid #{sid}"
        elsif sub.present?
          ActiveSession.where(sub: sub).destroy_all
          Rails.logger.info "Backchannel logout success: terminated active sessions for sub #{sub}"
        end
        head :ok
      else
        head :bad_request
      end
    rescue JWT::DecodeError => e
      Rails.logger.error "Backchannel logout token verification failed: #{e.message}"
      head :bad_request
    end
  end

  def failure
    redirect_to root_path, alert: "Authentication failed: #{params[:message]}"
  end

  private

  def validate_logout_token(claims)
    oidc = Rails.configuration.x.oidc

    # 1. Verify issuer
    if claims['iss'] != oidc.issuer
      Rails.logger.error "Logout token validation failed: issuer mismatch. Expected #{oidc.issuer}, got #{claims['iss']}"
      return false
    end
    
    # 2. Verify audience
    if claims['aud'] != oidc.client_id && !Array(claims['aud']).include?(oidc.client_id)
      Rails.logger.error "Logout token validation failed: audience mismatch. Expected #{oidc.client_id}, got #{claims['aud']}"
      return false
    end
    
    # 3. Verify events
    unless claims['events']&.key?("http://schemas.openid.net/event/backchannel-logout")
      Rails.logger.error "Logout token validation failed: missing backchannel-logout event claim"
      return false
    end
    
    # 4. Verify no nonce
    if claims.key?('nonce')
      Rails.logger.error "Logout token validation failed: contains prohibited nonce claim"
      return false
    end
    
    # 5. Verify sub or sid is present
    if claims['sub'].blank? && claims['sid'].blank?
      Rails.logger.error "Logout token validation failed: both sub and sid claims are missing"
      return false
    end
    
    true
  end
end
