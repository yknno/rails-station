class LoggedOutJti < ApplicationRecord
  validates :jti, presence: true, uniqueness: true
  validates :expires_at, presence: true

  # Class method to clean up expired JTIs periodically
  def self.prune_expired
    where("expires_at < ?", Time.current).delete_all
  end
end
