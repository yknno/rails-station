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

    # OidcService を使用して JWKS を取得し、ID トークンの署名と標準クレームを検証します。
    begin
      decoded_payload = OidcService.decode_and_verify(raw_id_token, {
        aud: oidc.client_id,
        verify_aud: true,
        iss: oidc.issuer,
        verify_iss: true
      })
    rescue OidcService::JwksUnavailableError => e
      redirect_to root_path, alert: "Authentication failed: Identity provider keys are currently unavailable. Please try again later."
      return
    rescue JWT::DecodeError => e
      redirect_to root_path, alert: "ID Token verification failed: #{e.message}"
      return
    end

    # 有効期限と OIDC セッション識別子 (sid) を抽出します。
    expires_at = Time.at(decoded_payload['exp']) if decoded_payload['exp'].present?
    expires_at ||= 1.hour.from_now
    
    sid = decoded_payload['sid']
    sub = decoded_payload['sub']

    # アクティブセッションレコードを作成します。
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
      # OidcService を使用して JWKS (キャッシュ) を取得し、署名検証を伴ってデコード
      decoded_token = OidcService.decode_and_verify(logout_token)

      # jti を使用したリプレイ攻撃防止
      jti = decoded_token["jti"]
      if jti.blank?
        Rails.logger.error "Backchannel logout validation failed: missing jti claim"
        head :bad_request
        return
      end

      if LoggedOutJti.exists?(jti: jti)
        Rails.logger.error "Backchannel logout validation failed: replayed jti #{jti}"
        head :bad_request
        return
      end

      # OIDC Back-Channel Logout 1.0 に従ったクレーム検証の実行
      if validate_logout_token(decoded_token)
        # トークンの exp から有効期限を算出し、未設定の場合はデフォルトで 24 時間に設定
        token_expires_at = decoded_token["exp"].present? ? Time.at(decoded_token["exp"]) : 24.hours.from_now

        # リプレイ攻撃防止のために JTI をデータベースに記録（ユニーク制約の競合は例外捕捉でハンドリング）
        begin
          LoggedOutJti.create!(jti: jti, expires_at: token_expires_at)
        rescue ActiveRecord::RecordNotUnique
          Rails.logger.error "Backchannel logout validation failed: replayed jti #{jti} (race condition)"
          head :bad_request
          return
        end

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
    rescue OidcService::JwksUnavailableError => e
      Rails.logger.error "Backchannel logout failed due to JWKS unavailability: #{e.message}"
      head :service_unavailable
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

    # 1. issuer (iss) の検証
    if claims['iss'] != oidc.issuer
      Rails.logger.error "Logout token validation failed: issuer mismatch. Expected #{oidc.issuer}, got #{claims['iss']}"
      return false
    end
    
    # 2. audience (aud) の検証
    if claims['aud'] != oidc.client_id && !Array(claims['aud']).include?(oidc.client_id)
      Rails.logger.error "Logout token validation failed: audience mismatch. Expected #{oidc.client_id}, got #{claims['aud']}"
      return false
    end
    
    # 3. events の検証
    unless claims['events']&.key?("http://schemas.openid.net/event/backchannel-logout")
      Rails.logger.error "Logout token validation failed: missing backchannel-logout event claim"
      return false
    end
    
    # 4. nonce が含まれていないことの検証
    if claims.key?('nonce')
      Rails.logger.error "Logout token validation failed: contains prohibited nonce claim"
      return false
    end
    
    # 5. iat が現在時刻に近いことの検証（古いトークンの再利用を防ぐために±5分以内とする）
    iat = claims['iat'].to_i
    now = Time.now.to_i
    if iat.zero? || (iat - now).abs > 5.minutes.to_i
      Rails.logger.error "Logout token validation failed: iat is not close to current time. iat: #{iat}, now: #{now}"
      return false
    end
    
    # 6. sub または sid のいずれかが存在することの検証
    if claims['sub'].blank? && claims['sid'].blank?
      Rails.logger.error "Logout token validation failed: both sub and sid claims are missing"
      return false
    end
    
    true
  end
end
