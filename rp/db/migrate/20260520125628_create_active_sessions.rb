class CreateActiveSessions < ActiveRecord::Migration[8.1]
  def change
    drop_table :revoked_sessions, if_exists: true

    create_table :active_sessions do |t|
      t.string :sid
      t.string :user_email
      t.text :raw_id_token
      t.datetime :expires_at
      t.text :claims

      t.timestamps
    end
    add_index :active_sessions, :sid
  end
end
