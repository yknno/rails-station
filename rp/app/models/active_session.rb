require "jwt"

class ActiveSession < ApplicationRecord
  belongs_to :account
  delegate :sub, to: :account

  def expired?
    expires_at.present? && expires_at < Time.current
  end

  # 有効期限が切れたアクティブセッションレコードを削除するクラスメソッド。
  # TODO: テーブルの肥大化を防ぐため、このメソッドを非同期ジョブなどで定期的に呼び出してください。
  def self.prune_expired
    where("expires_at < ?", Time.current).delete_all
  end

  def self.create_from_id_token!(raw_id_token, decoded_payload)
    sub = decoded_payload['sub']
    account = Account.find_or_create_by!(sub: sub)
    expires_at = decoded_payload['exp'].present? ? Time.at(decoded_payload['exp']) : 1.hour.from_now
    create!(
      account: account,
      sid: decoded_payload['sid'],
      raw_id_token: raw_id_token,
      expires_at: expires_at
    )
  end

  # raw_id_token はログイン時に omniauth_openid_connect が署名検証済み。
  # 表示用にクレームを読み出すだけなので、ここでは署名の再検証はしない。
  def claims
    return {} if raw_id_token.blank?
    @claims ||= JWT.decode(raw_id_token, nil, false).first
  rescue JWT::DecodeError => e
    Rails.logger.error "Failed to decode stored ID token: #{e.message}"
    {}
  end

  def user_email
    claims["email"]
  end
end
