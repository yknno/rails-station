require "test_helper"
require "jwt"
require "minitest/mock"

class SessionsControllerTest < ActionDispatch::IntegrationTest
  setup do
    @jwks_hash = { "keys" => [] }
    @account = Account.create!(sub: "1")

    @mock_payload = {
      "iss" => "http://localhost:4444/",
      "sub" => "1",
      "aud" => "rp-client",
      "exp" => (Time.now.to_i + 3600),
      "sid" => "session-123",
      "email" => "user@example.com"
    }
  end

  test "OIDC callback creates active session when token is valid" do
    # Configure OmniAuth mock
    OmniAuth.config.test_mode = true
    OmniAuth.config.mock_auth[:openid_connect] = OmniAuth::AuthHash.new({
      provider: "openid_connect",
      uid: "1",
      info: { email: "user@example.com" },
      credentials: { id_token: "mock-id-token" }
    })

    # The ID token is already verified by omniauth_openid_connect; the controller
    # only decodes it (without re-verifying) to extract sid / sub / exp.
    JWT.stub(:decode, [@mock_payload, { "alg" => "RS256" }]) do
      assert_difference "ActiveSession.count", 1 do
        post "/auth/openid_connect/callback"
      end

      created_session = ActiveSession.last
      assert_equal "session-123", created_session.sid
      assert_equal "1", created_session.sub
      assert_equal "user@example.com", created_session.user_email
      assert_equal @mock_payload, created_session.claims
    end

    assert_redirected_to root_path
    assert_equal "Logged in successfully via OIDC!", flash[:notice]
  end

  test "backchannel logout destroys active session when token is valid" do
    ActiveSession.create!(
      account: @account,
      sid: "session-123",
      raw_id_token: "mock-id-token",
      expires_at: 1.hour.from_now
    )

    logout_claims = {
      "iss" => "http://localhost:4444/",
      "aud" => "rp-client",
      "exp" => Time.now.to_i + 3600,
      "iat" => Time.now.to_i,
      "jti" => "logout-123",
      "sid" => "session-123",
      "events" => {
        "http://schemas.openid.net/event/backchannel-logout" => {}
      }
    }

    Oidc::JwksProvider.stub(:http_get_jwks, @jwks_hash) do
      JWT::JWK::Set.stub(:new, Object.new) do
        JWT.stub(:decode, [logout_claims, { "alg" => "RS256" }]) do
          assert_difference "ActiveSession.count", -1 do
            post "/auth/backchannel_logout", params: { logout_token: "mock-logout-token" }
          end
        end
      end
    end

    assert_response :success
    assert_equal "no-store", response.headers["Cache-Control"]
    assert_equal "no-cache", response.headers["Pragma"]
  end

  test "backchannel logout by sub destroys active session when token is valid" do
    ActiveSession.create!(
      account: @account,
      raw_id_token: "mock-id-token",
      expires_at: 1.hour.from_now
    )

    logout_claims = {
      "iss" => "http://localhost:4444/",
      "aud" => "rp-client",
      "exp" => Time.now.to_i + 3600,
      "iat" => Time.now.to_i,
      "jti" => "logout-124",
      "sub" => "1",
      "events" => {
        "http://schemas.openid.net/event/backchannel-logout" => {}
      }
    }

    Oidc::JwksProvider.stub(:http_get_jwks, @jwks_hash) do
      JWT::JWK::Set.stub(:new, Object.new) do
        JWT.stub(:decode, [logout_claims, { "alg" => "RS256" }]) do
          assert_difference "ActiveSession.count", -1 do
            post "/auth/backchannel_logout", params: { logout_token: "mock-logout-token" }
          end
        end
      end
    end

    assert_response :success
  end

  test "backchannel logout prevents replay attacks with duplicate jti" do
    ActiveSession.create!(
      account: @account,
      sid: "session-123",
      raw_id_token: "mock-id-token",
      expires_at: 1.hour.from_now
    )

    logout_claims = {
      "iss" => "http://localhost:4444/",
      "aud" => "rp-client",
      "exp" => Time.now.to_i + 3600,
      "iat" => Time.now.to_i,
      "jti" => "logout-unique-replay",
      "sid" => "session-123",
      "events" => {
        "http://schemas.openid.net/event/backchannel-logout" => {}
      }
    }

    # First request
    Oidc::JwksProvider.stub(:http_get_jwks, @jwks_hash) do
      JWT::JWK::Set.stub(:new, Object.new) do
        JWT.stub(:decode, [logout_claims, { "alg" => "RS256" }]) do
          post "/auth/backchannel_logout", params: { logout_token: "mock-logout-token" }
          assert_response :success
        end
      end
    end

    # Second request with duplicate jti
    Oidc::JwksProvider.stub(:http_get_jwks, @jwks_hash) do
      JWT::JWK::Set.stub(:new, Object.new) do
        JWT.stub(:decode, [logout_claims, { "alg" => "RS256" }]) do
          post "/auth/backchannel_logout", params: { logout_token: "mock-logout-token" }
          assert_response :bad_request
          assert_equal "no-store", response.headers["Cache-Control"]
          assert_equal "no-cache", response.headers["Pragma"]
        end
      end
    end
  end

  test "backchannel logout fails when token has nonce claim" do
    ActiveSession.create!(
      account: @account,
      sid: "session-123",
      raw_id_token: "mock-id-token",
      expires_at: 1.hour.from_now
    )

    invalid_claims = {
      "iss" => "http://localhost:4444/",
      "aud" => "rp-client",
      "exp" => Time.now.to_i + 3600,
      "iat" => Time.now.to_i,
      "jti" => "logout-nonce-fail",
      "sid" => "session-123",
      "nonce" => "some-nonce",
      "events" => {
        "http://schemas.openid.net/event/backchannel-logout" => {}
      }
    }

    Oidc::JwksProvider.stub(:http_get_jwks, @jwks_hash) do
      JWT::JWK::Set.stub(:new, Object.new) do
        JWT.stub(:decode, [invalid_claims, { "alg" => "RS256" }]) do
          assert_no_difference "ActiveSession.count" do
            post "/auth/backchannel_logout", params: { logout_token: "mock-logout-token" }
          end
        end
      end
    end

    assert_response :bad_request
    assert_equal "no-store", response.headers["Cache-Control"]
    assert_equal "no-cache", response.headers["Pragma"]
  end

  test "backchannel logout fails when token iat is too far in the past" do
    ActiveSession.create!(
      account: @account,
      sid: "session-123",
      raw_id_token: "mock-id-token",
      expires_at: 1.hour.from_now
    )

    invalid_claims = {
      "iss" => "http://localhost:4444/",
      "aud" => "rp-client",
      "exp" => Time.now.to_i + 3600,
      "iat" => 6.minutes.ago.to_i,
      "jti" => "logout-iat-past-fail",
      "sid" => "session-123",
      "events" => {
        "http://schemas.openid.net/event/backchannel-logout" => {}
      }
    }

    Oidc::JwksProvider.stub(:http_get_jwks, @jwks_hash) do
      JWT::JWK::Set.stub(:new, Object.new) do
        JWT.stub(:decode, [invalid_claims, { "alg" => "RS256" }]) do
          assert_no_difference "ActiveSession.count" do
            post "/auth/backchannel_logout", params: { logout_token: "mock-logout-token" }
          end
        end
      end
    end

    assert_response :bad_request
  end

  test "backchannel logout fails when token iat is too far in the future" do
    ActiveSession.create!(
      account: @account,
      sid: "session-123",
      raw_id_token: "mock-id-token",
      expires_at: 1.hour.from_now
    )

    invalid_claims = {
      "iss" => "http://localhost:4444/",
      "aud" => "rp-client",
      "exp" => Time.now.to_i + 3600,
      "iat" => 6.minutes.from_now.to_i,
      "jti" => "logout-iat-future-fail",
      "sid" => "session-123",
      "events" => {
        "http://schemas.openid.net/event/backchannel-logout" => {}
      }
    }

    Oidc::JwksProvider.stub(:http_get_jwks, @jwks_hash) do
      JWT::JWK::Set.stub(:new, Object.new) do
        JWT.stub(:decode, [invalid_claims, { "alg" => "RS256" }]) do
          assert_no_difference "ActiveSession.count" do
            post "/auth/backchannel_logout", params: { logout_token: "mock-logout-token" }
          end
        end
      end
    end

    assert_response :bad_request
  end

  test "backchannel logout returns service unavailable when JWKS cannot be fetched" do
    ActiveSession.create!(
      account: @account,
      sid: "session-123",
      raw_id_token: "mock-id-token",
      expires_at: 1.hour.from_now
    )

    Oidc::JwksProvider.stub(:http_get_jwks, nil) do
      assert_no_difference "ActiveSession.count" do
        post "/auth/backchannel_logout", params: { logout_token: "mock-logout-token" }
      end
    end

    assert_response :service_unavailable
    assert_equal "no-store", response.headers["Cache-Control"]
    assert_equal "no-cache", response.headers["Pragma"]
  end

  test "OIDC callback creates new Account when it does not exist" do
    OmniAuth.config.test_mode = true
    OmniAuth.config.mock_auth[:openid_connect] = OmniAuth::AuthHash.new({
      provider: "openid_connect",
      uid: "2",
      info: { email: "new@example.com" },
      credentials: { id_token: "mock-id-token" }
    })

    new_payload = @mock_payload.merge("sub" => "new-sub", "email" => "new@example.com")
    
    JWT.stub(:decode, [new_payload, { "alg" => "RS256" }]) do
      assert_difference "Account.count", 1 do
        assert_difference "ActiveSession.count", 1 do
          post "/auth/openid_connect/callback"
        end
      end
    end
  end

  test "backchannel logout destroys active sessions but keeps Account record" do
    ActiveSession.create!(
      account: @account,
      sid: "session-123",
      raw_id_token: "mock-id-token",
      expires_at: 1.hour.from_now
    )

    logout_claims = {
      "iss" => "http://localhost:4444/",
      "aud" => "rp-client",
      "exp" => Time.now.to_i + 3600,
      "iat" => Time.now.to_i,
      "jti" => "logout-123",
      "sid" => "session-123",
      "events" => {
        "http://schemas.openid.net/event/backchannel-logout" => {}
      }
    }

    Oidc::JwksProvider.stub(:http_get_jwks, @jwks_hash) do
      JWT::JWK::Set.stub(:new, Object.new) do
        JWT.stub(:decode, [logout_claims, { "alg" => "RS256" }]) do
          assert_difference "ActiveSession.count", -1 do
            assert_no_difference "Account.count" do
              post "/auth/backchannel_logout", params: { logout_token: "mock-logout-token" }
            end
          end
        end
      end
    end
  end
end
