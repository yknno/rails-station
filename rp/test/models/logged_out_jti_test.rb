require "test_helper"

class LoggedOutJtiTest < ActiveSupport::TestCase
  test "should be valid with unique jti and expires_at" do
    jti = LoggedOutJti.new(jti: "test-jti", expires_at: 1.hour.from_now)
    assert jti.valid?
  end

  test "should be invalid without jti" do
    jti = LoggedOutJti.new(expires_at: 1.hour.from_now)
    assert_not jti.valid?
  end

  test "should be invalid without expires_at" do
    jti = LoggedOutJti.new(jti: "test-jti")
    assert_not jti.valid?
  end

  test "should enforce unique jti" do
    LoggedOutJti.create!(jti: "dup-jti", expires_at: 1.hour.from_now)
    dup = LoggedOutJti.new(jti: "dup-jti", expires_at: 1.hour.from_now)
    assert_not dup.valid?
  end

  test "should prune expired records" do
    LoggedOutJti.delete_all
    LoggedOutJti.create!(jti: "expired-jti", expires_at: 1.minute.ago)
    LoggedOutJti.create!(jti: "active-jti", expires_at: 10.minutes.from_now)

    assert_difference "LoggedOutJti.count", -1 do
      LoggedOutJti.prune_expired
    end

    assert LoggedOutJti.exists?(jti: "active-jti")
    assert_not LoggedOutJti.exists?(jti: "expired-jti")
  end
end
