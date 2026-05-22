# This file is auto-generated from the current state of the database. Instead
# of editing this file, please use the migrations feature of Active Record to
# incrementally modify your database, and then regenerate this schema definition.
#
# This file is the source Rails uses to define your schema when running `bin/rails
# db:schema:load`. When creating a new database, `bin/rails db:schema:load` tends to
# be faster and is potentially less error prone than running all of your
# migrations from scratch. Old migrations may fail to apply correctly if those
# migrations use external dependencies or application code.
#
# It's strongly recommended that you check this file into your version control system.

ActiveRecord::Schema[8.1].define(version: 2026_05_22_124231) do
  create_table "accounts", force: :cascade do |t|
    t.datetime "created_at", null: false
    t.string "sub", null: false
    t.datetime "updated_at", null: false
    t.index ["sub"], name: "index_accounts_on_sub", unique: true
  end

  create_table "active_sessions", force: :cascade do |t|
    t.integer "account_id", null: false
    t.datetime "created_at", null: false
    t.datetime "expires_at"
    t.text "raw_id_token"
    t.string "sid"
    t.datetime "updated_at", null: false
    t.index ["account_id"], name: "index_active_sessions_on_account_id"
    t.index ["sid"], name: "index_active_sessions_on_sid"
  end

  create_table "logged_out_jtis", force: :cascade do |t|
    t.datetime "created_at", null: false
    t.datetime "expires_at"
    t.string "jti"
    t.datetime "updated_at", null: false
    t.index ["expires_at"], name: "index_logged_out_jtis_on_expires_at"
    t.index ["jti"], name: "index_logged_out_jtis_on_jti", unique: true
  end

  add_foreign_key "active_sessions", "accounts"
end
