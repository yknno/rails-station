class CreateRevokedSessions < ActiveRecord::Migration[8.1]
  def change
    create_table :revoked_sessions do |t|
      t.string :sid

      t.timestamps
    end
    add_index :revoked_sessions, :sid
  end
end
