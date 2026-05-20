require "test_helper"

class ActiveSessionTest < ActiveSupport::TestCase
  test "should be expired when expires_at is in the past" do
    session = ActiveSession.new(
      sid: "test-sid",
      user_email: "test@example.com",
      expires_at: 1.minute.ago,
      claims: { email: "test@example.com" }
    )
    assert session.expired?
  end

  test "should not be expired when expires_at is in the future" do
    session = ActiveSession.new(
      sid: "test-sid",
      user_email: "test@example.com",
      expires_at: 10.minutes.from_now,
      claims: { email: "test@example.com" }
    )
    assert_not session.expired?
  end

  test "should serialize and deserialize claims correctly" do
    claims_hash = { "email" => "test@example.com", "name" => "Test User", "sub" => "123" }
    session = ActiveSession.create!(
      sid: "test-sid",
      user_email: "test@example.com",
      expires_at: 1.hour.from_now,
      claims: claims_hash
    )
    
    loaded_session = ActiveSession.find(session.id)
    assert_equal claims_hash, loaded_session.claims
  end
end
