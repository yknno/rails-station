class CreateAccountsAndUpdateActiveSessions < ActiveRecord::Migration[8.1]
  def up
    # 1. Create accounts table
    create_table :accounts do |t|
      t.string :sub, null: false
      t.timestamps
    end
    add_index :accounts, :sub, unique: true

    # 2. Add temporary nullable account_id to active_sessions
    add_reference :active_sessions, :account, foreign_key: true, null: true

    # 3. Migrate existing data: Create Account records for each unique sub and link them
    execute <<~SQL
      INSERT INTO accounts (sub, created_at, updated_at)
      SELECT DISTINCT sub, datetime('now'), datetime('now') FROM active_sessions
      WHERE sub IS NOT NULL;
    SQL

    execute <<~SQL
      UPDATE active_sessions
      SET account_id = (SELECT id FROM accounts WHERE accounts.sub = active_sessions.sub)
      WHERE sub IS NOT NULL;
    SQL

    # Remove any active_sessions that do not have an associated account (if any exist)
    execute "DELETE FROM active_sessions WHERE account_id IS NULL;"

    # 4. Change account_id to be non-nullable
    change_column_null :active_sessions, :account_id, false

    # 5. Remove sub from active_sessions
    remove_column :active_sessions, :sub, :string
  end

  def down
    # Restore sub to active_sessions
    add_column :active_sessions, :sub, :string
    add_index :active_sessions, :sub

    # Restore data from accounts
    execute <<~SQL
      UPDATE active_sessions
      SET sub = (SELECT sub FROM accounts WHERE accounts.id = active_sessions.account_id);
    SQL

    # Remove account_id
    remove_reference :active_sessions, :account, foreign_key: true

    # Drop accounts table
    drop_table :accounts
  end
end

