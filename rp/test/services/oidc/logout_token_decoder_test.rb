require "test_helper"

class Oidc::LogoutTokenDecoderTest < ActiveSupport::TestCase
  setup do
    @jwks_hash = { "keys" => [] }
    @jwks_uri = "http://localhost:4444/jwks"
    oidc_class = Struct.new(:issuer, :client_id, :jwks_uri)
    @oidc_config = oidc_class.new(
      "http://localhost:4444/",
      "rp-client",
      @jwks_uri
    )
  end

  test "decode decodes and validates logout token claims" do
    claims = {
      "iss" => "http://localhost:4444/",
      "aud" => "rp-client",
      "iat" => Time.now.to_i,
      "exp" => (Time.now.to_i + 3600),
      "jti" => "logout-jti-123",
      "sid" => "session-123",
      "events" => {
        "http://schemas.openid.net/event/backchannel-logout" => {}
      }
    }
    Oidc::JwksProvider.stub(:http_get_jwks, @jwks_hash) do
      JWT.stub(:decode, [claims, { "alg" => "RS256" }]) do
        decoded = Oidc::LogoutTokenDecoder.decode("mock-logout-token", @oidc_config)
        assert_equal claims, decoded
      end
    end
  end

  test "decode raises TokenValidationError when exp is missing" do
    invalid_claims = {
      "iss" => "http://localhost:4444/",
      "aud" => "rp-client",
      "iat" => Time.now.to_i,
      "jti" => "logout-jti-123",
      "sid" => "session-123",
      "events" => {
        "http://schemas.openid.net/event/backchannel-logout" => {}
      }
    }
    Oidc::JwksProvider.stub(:http_get_jwks, @jwks_hash) do
      JWT.stub(:decode, [invalid_claims, { "alg" => "RS256" }]) do
        assert_raises Oidc::TokenValidationError do
          Oidc::LogoutTokenDecoder.decode("mock-logout-token", @oidc_config)
        end
      end
    end
  end

  test "decode raises TokenValidationError on invalid claims" do
    invalid_claims = {
      "iss" => "http://invalid-issuer.com/",
      "aud" => "rp-client",
      "iat" => Time.now.to_i,
      "jti" => "logout-jti-123",
      "sid" => "session-123",
      "events" => {
        "http://schemas.openid.net/event/backchannel-logout" => {}
      }
    }
    Oidc::JwksProvider.stub(:http_get_jwks, @jwks_hash) do
      JWT.stub(:decode, [invalid_claims, { "alg" => "RS256" }]) do
        assert_raises Oidc::TokenValidationError do
          Oidc::LogoutTokenDecoder.decode("mock-logout-token", @oidc_config)
        end
      end
    end
  end

  test "decode raises TokenValidationError when events is not a hash" do
    invalid_claims = {
      "iss" => "http://localhost:4444/",
      "aud" => "rp-client",
      "iat" => Time.now.to_i,
      "jti" => "logout-jti-123",
      "sid" => "session-123",
      "events" => "not-a-hash"
    }
    Oidc::JwksProvider.stub(:http_get_jwks, @jwks_hash) do
      JWT.stub(:decode, [invalid_claims, { "alg" => "RS256" }]) do
        assert_raises Oidc::TokenValidationError do
          Oidc::LogoutTokenDecoder.decode("mock-logout-token", @oidc_config)
        end
      end
    end
  end

  test "decode raises TokenValidationError when backchannel-logout event claim is not a hash" do
    invalid_claims = {
      "iss" => "http://localhost:4444/",
      "aud" => "rp-client",
      "iat" => Time.now.to_i,
      "jti" => "logout-jti-123",
      "sid" => "session-123",
      "events" => {
        "http://schemas.openid.net/event/backchannel-logout" => "not-a-hash"
      }
    }
    Oidc::JwksProvider.stub(:http_get_jwks, @jwks_hash) do
      JWT.stub(:decode, [invalid_claims, { "alg" => "RS256" }]) do
        assert_raises Oidc::TokenValidationError do
          Oidc::LogoutTokenDecoder.decode("mock-logout-token", @oidc_config)
        end
      end
    end
  end
end
