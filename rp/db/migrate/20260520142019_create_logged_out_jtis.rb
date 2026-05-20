class CreateLoggedOutJtis < ActiveRecord::Migration[8.1]
  def change
    create_table :logged_out_jtis do |t|
      t.string :jti
      t.datetime :expires_at

      t.timestamps
    end
    add_index :logged_out_jtis, :jti, unique: true
    add_index :logged_out_jtis, :expires_at
  end
end
