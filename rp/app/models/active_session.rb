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
    OidcService.decode_and_verify(raw_id_token, {
      aud: oidc.client_id,
      verify_aud: true,
      iss: oidc.issuer,
      verify_iss: true
    })
  rescue => e
    Rails.logger.error "ActiveSession ID token verification failed: #{e.message}"
    {}
  end
end
