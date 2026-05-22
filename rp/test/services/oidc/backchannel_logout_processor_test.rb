require "test_helper"

class Oidc::BackchannelLogoutProcessorTest < ActiveSupport::TestCase
  setup do
    @jwks_hash = { "keys" => [] }
    @jwks_uri = "http://localhost:4444/jwks"
    oidc_class = Struct.new(:issuer, :client_id, :jwks_uri)
    @oidc_config = oidc_class.new(
      "http://localhost:4444/",
      "rp-client",
      @jwks_uri
    )
    @account = Account.create!(sub: "1")
  end

  test "process destroys active session by sid when token is valid" do
    ActiveSession.create!(
      account: @account,
      sid: "session-123",
      raw_id_token: "mock-id-token",
      expires_at: 1.hour.from_now
    )

    logout_claims = {
      "iss" => "http://localhost:4444/",
      "aud" => "rp-client",
      "iat" => Time.now.to_i,
      "jti" => "logout-123",
      "sid" => "session-123",
      "events" => {
        "http://schemas.openid.net/event/backchannel-logout" => {}
      }
    }

    Oidc::JwksProvider.stub(:http_get_jwks, @jwks_hash) do
      JWT.stub(:decode, [logout_claims, { "alg" => "RS256" }]) do
        assert_difference "ActiveSession.count", -1 do
          Oidc::BackchannelLogoutProcessor.process("mock-logout-token", @oidc_config)
        end
      end
    end
  end

  test "process destroys active session by sub when token is valid" do
    ActiveSession.create!(
      account: @account,
      raw_id_token: "mock-id-token",
      expires_at: 1.hour.from_now
    )

    logout_claims = {
      "iss" => "http://localhost:4444/",
      "aud" => "rp-client",
      "iat" => Time.now.to_i,
      "jti" => "logout-124",
      "sub" => "1",
      "events" => {
        "http://schemas.openid.net/event/backchannel-logout" => {}
      }
    }

    Oidc::JwksProvider.stub(:http_get_jwks, @jwks_hash) do
      JWT.stub(:decode, [logout_claims, { "alg" => "RS256" }]) do
        assert_difference "ActiveSession.count", -1 do
          Oidc::BackchannelLogoutProcessor.process("mock-logout-token", @oidc_config)
        end
      end
    end
  end

  test "process prevents replay attacks with duplicate jti" do
    ActiveSession.create!(
      account: @account,
      sid: "session-123",
      raw_id_token: "mock-id-token",
      expires_at: 1.hour.from_now
    )

    logout_claims = {
      "iss" => "http://localhost:4444/",
      "aud" => "rp-client",
      "iat" => Time.now.to_i,
      "jti" => "logout-unique-replay",
      "sid" => "session-123",
      "events" => {
        "http://schemas.openid.net/event/backchannel-logout" => {}
      }
    }

    Oidc::JwksProvider.stub(:http_get_jwks, @jwks_hash) do
      JWT.stub(:decode, [logout_claims, { "alg" => "RS256" }]) do
        # First execution
        Oidc::BackchannelLogoutProcessor.process("mock-logout-token", @oidc_config)
        
        # Second execution (replayed)
        assert_raises Oidc::ReplayAttackError do
          Oidc::BackchannelLogoutProcessor.process("mock-logout-token", @oidc_config)
        end
      end
    end
  end
end
