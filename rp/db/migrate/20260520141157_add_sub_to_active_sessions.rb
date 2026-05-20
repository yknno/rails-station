class AddSubToActiveSessions < ActiveRecord::Migration[8.1]
  def change
    add_column :active_sessions, :sub, :string
    add_index :active_sessions, :sub
  end
end
