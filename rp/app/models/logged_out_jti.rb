class LoggedOutJti < ApplicationRecord
  validates :jti, presence: true, uniqueness: true
  validates :expires_at, presence: true

  # 有効期限が切れた JTI レコードを削除するクラスメソッド。
  # TODO: テーブルの肥大化を防ぐため、このメソッドを非同期ジョブなどで定期的に呼び出してください。
  def self.prune_expired
    where("expires_at < ?", Time.current).delete_all
  end
end
