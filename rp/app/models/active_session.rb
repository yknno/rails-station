class ActiveSession < ApplicationRecord
  serialize :claims, type: Hash, coder: JSON

  def expired?
    expires_at.present? && expires_at < Time.current
  end
end
