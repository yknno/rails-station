require "jwt"
require "net/http"

class ActiveSession < ApplicationRecord
  def expired?
    expires_at.present? && expires_at < Time.current
  end

  # 有効期限が切れたアクティブセッションレコードを削除するクラスメソッド。
  # TODO: テーブルの肥大化を防ぐため、このメソッドを非同期ジョブなどで定期的に呼び出してください。
  def self.prune_expired
    where("expires_at < ?", Time.current).delete_all
  end

  def self.create_from_id_token!(raw_id_token, decoded_payload)
    expires_at = decoded_payload['exp'].present? ? Time.at(decoded_payload['exp']) : 1.hour.from_now
    create!(
      sid: decoded_payload['sid'],
      sub: decoded_payload['sub'],
      raw_id_token: raw_id_token,
      expires_at: expires_at
    )
  end

  def claims
    return {} if raw_id_token.blank?
    @claims ||= decode_and_verify_id_token
  end

  def user_email
    claims["email"]
  end

  private

  def decode_and_verify_id_token
    oidc = Rails.configuration.x.oidc
    Oidc::IdTokenDecoder.decode(raw_id_token, oidc)
  rescue => e
    Rails.logger.error "ActiveSession ID token verification failed: #{e.message}"
    {}
  end
end
