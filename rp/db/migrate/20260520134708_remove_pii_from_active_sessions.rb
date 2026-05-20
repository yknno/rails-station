class RemovePiiFromActiveSessions < ActiveRecord::Migration[8.1]
  def change
    remove_column :active_sessions, :claims, :text
    remove_column :active_sessions, :user_email, :string
  end
end
