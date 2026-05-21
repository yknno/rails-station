require "test_helper"
require "jwt"
require "minitest/mock"

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
      sub: "123",
      expires_at: 1.hour.from_now,
      raw_id_token: @token
    )
    
    # Mock JWKS and stub decode to return our claims
    Rails.cache.stub(:fetch, { keys: [] }) do
      JWT.stub(:decode, [@claims_hash, { "alg" => "RS256" }]) do
        loaded_session = ActiveSession.find(session.id)
        assert_equal "123", loaded_session.sub
        assert_equal @claims_hash, loaded_session.claims
        assert_equal "test@example.com", loaded_session.user_email
      end
    end
  end

  test "prune_expired deletes expired sessions and keeps active ones" do
    ActiveSession.create!(sid: "expired-1", raw_id_token: "token-1", expires_at: 1.minute.ago)
    ActiveSession.create!(sid: "active-1", raw_id_token: "token-2", expires_at: 1.minute.from_now)

    assert_difference "ActiveSession.count", -1 do
      ActiveSession.prune_expired
    end
  end

  test "create_from_id_token! creates session correctly" do
    decoded_payload = {
      "sub" => "123",
      "sid" => "test-sid",
      "exp" => Time.now.to_i + 3600
    }
    
    assert_difference "ActiveSession.count", 1 do
      ActiveSession.create_from_id_token!("mock-raw-id-token", decoded_payload)
    end
    
    session = ActiveSession.last
    assert_equal "123", session.sub
    assert_equal "test-sid", session.sid
    assert_equal "mock-raw-id-token", session.raw_id_token
    assert_in_delta Time.at(decoded_payload["exp"]), session.expires_at, 2.seconds
  end

  test "create_from_id_token! falls back to 1 hour from now if exp is missing" do
    decoded_payload = {
      "sub" => "123",
      "sid" => "test-sid"
    }
    
    assert_difference "ActiveSession.count", 1 do
      ActiveSession.create_from_id_token!("mock-raw-id-token", decoded_payload)
    end
    
    session = ActiveSession.last
    assert_in_delta 1.hour.from_now, session.expires_at, 5.seconds
  end
end
