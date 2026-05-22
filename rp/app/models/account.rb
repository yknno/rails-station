class Account < ApplicationRecord
  has_many :active_sessions, dependent: :destroy

  validates :sub, presence: true, uniqueness: true
end
