require "test_helper"

class AccountTest < ActiveSupport::TestCase
  test "valid account requires sub" do
    account = Account.new
    assert_not account.valid?
    assert_includes account.errors[:sub], "can't be blank"
  end

  test "sub must be unique" do
    Account.create!(sub: "unique-sub")
    duplicate = Account.new(sub: "unique-sub")
    assert_not duplicate.valid?
    assert_includes duplicate.errors[:sub], "has already been taken"
  end

  test "destroying account destroys associated active sessions" do
    account = Account.create!(sub: "test-user")
    ActiveSession.create!(account: account, sid: "session-1", raw_id_token: "token-1", expires_at: 1.hour.from_now)
    ActiveSession.create!(account: account, sid: "session-2", raw_id_token: "token-2", expires_at: 1.hour.from_now)

    assert_difference "ActiveSession.count", -2 do
      account.destroy
    end
  end
end
