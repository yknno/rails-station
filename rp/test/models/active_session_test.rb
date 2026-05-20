require "test_helper"
require "jwt"

class ActiveSessionTest < ActiveSupport::TestCase
  setup do
    @claims_hash = { "email" => "test@example.com", "name" => "Test User", "sub" => "123" }
    # Generate a dummy HS256-signed JWT token for testing
    @token = JWT.encode(@claims_hash, "secret", "HS256")
  end

  test "should be expired when expires_at is in the past" do
    session = ActiveSession.new(
      sid: "test-sid",
      expires_at: 1.minute.ago,
      raw_id_token: @token
    )
    assert session.expired?
  end

  test "should not be expired when expires_at is in the future" do
    session = ActiveSession.new(
      sid: "test-sid",
      expires_at: 10.minutes.from_now,
      raw_id_token: @token
    )
    assert_not session.expired?
  end

  test "should decode claims and email dynamically from raw_id_token" do
    session = ActiveSession.create!(
      sid: "test-sid",
      expires_at: 1.hour.from_now,
      raw_id_token: @token
    )
    
    loaded_session = ActiveSession.find(session.id)
    assert_equal @claims_hash, loaded_session.claims
    assert_equal "test@example.com", loaded_session.user_email
  end
end
