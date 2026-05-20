class LoggedOutJti < ApplicationRecord
  validates :jti, presence: true, uniqueness: true
  validates :expires_at, presence: true

  # Class method to clean up expired JTIs periodically.
  # TODO: Call this method periodically (e.g., via an hourly/daily Rake task or cron job in production)
  # to keep the table size bounded and prevent database bloat.
  def self.prune_expired
    where("expires_at < ?", Time.current).delete_all
  end
end
