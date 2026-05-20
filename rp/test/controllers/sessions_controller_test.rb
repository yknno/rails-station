require "test_helper"
require "jwt"

class SessionsControllerTest < ActionDispatch::IntegrationTest
  setup do
    @jwks_json = { keys: [] }.to_json

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

    stub_net_http_get(@jwks_json) do
      stub_jwk_set(Object.new) do
        stub_jwt_decode([@mock_payload, { "alg" => "RS256" }]) do
          assert_difference "ActiveSession.count", 1 do
            post "/auth/openid_connect/callback"
          end
        end
      end
    end

    assert_redirected_to root_path
    assert_equal "Logged in successfully via OIDC!", flash[:notice]

    created_session = ActiveSession.last
    assert_equal "session-123", created_session.sid
    assert_equal "user@example.com", created_session.user_email
    assert_equal @mock_payload, created_session.claims
  end

  test "backchannel logout destroys active session when token is valid" do
    active_session = ActiveSession.create!(
      sid: "session-123",
      user_email: "user@example.com",
      raw_id_token: "mock-id-token",
      expires_at: 1.hour.from_now,
      claims: @mock_payload
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

    stub_net_http_get(@jwks_json) do
      stub_jwk_set(Object.new) do
        stub_jwt_decode([logout_claims, { "alg" => "RS256" }]) do
          assert_difference "ActiveSession.count", -1 do
            post "/auth/backchannel_logout", params: { logout_token: "mock-logout-token" }
          end
        end
      end
    end

    assert_response :success
  end

  test "backchannel logout fails when token has nonce claim" do
    active_session = ActiveSession.create!(
      sid: "session-123",
      user_email: "user@example.com",
      raw_id_token: "mock-id-token",
      expires_at: 1.hour.from_now,
      claims: @mock_payload
    )

    invalid_claims = {
      "iss" => "http://localhost:4444/",
      "aud" => "rp-client",
      "iat" => Time.now.to_i,
      "sid" => "session-123",
      "nonce" => "some-nonce",
      "events" => {
        "http://schemas.openid.net/event/backchannel-logout" => {}
      }
    }

    stub_net_http_get(@jwks_json) do
      stub_jwk_set(Object.new) do
        stub_jwt_decode([invalid_claims, { "alg" => "RS256" }]) do
          assert_no_difference "ActiveSession.count" do
            post "/auth/backchannel_logout", params: { logout_token: "mock-logout-token" }
          end
        end
      end
    end

    assert_response :bad_request
  end

  private

  def stub_net_http_get(return_value)
    singleton = class << Net::HTTP; self; end
    singleton.class_eval do
      alias_method :original_get, :get rescue nil
      define_method(:get) { |*args| return_value }
    end
    yield
  ensure
    singleton = class << Net::HTTP; self; end
    singleton.class_eval do
      if method_defined?(:original_get)
        alias_method :get, :original_get
        remove_method :original_get
      end
    end
  end

  def stub_jwk_set(return_value)
    singleton = class << JWT::JWK::Set; self; end
    singleton.class_eval do
      alias_method :original_new, :new rescue nil
      define_method(:new) { |*args| return_value }
    end
    yield
  ensure
    singleton = class << JWT::JWK::Set; self; end
    singleton.class_eval do
      if method_defined?(:original_new)
        alias_method :new, :original_new
        remove_method :original_new
      end
    end
  end

  def stub_jwt_decode(return_value)
    singleton = class << JWT; self; end
    singleton.class_eval do
      alias_method :original_decode, :decode rescue nil
      define_method(:decode) { |*args| return_value }
    end
    yield
  ensure
    singleton = class << JWT; self; end
    singleton.class_eval do
      if method_defined?(:original_decode)
        alias_method :decode, :original_decode
        remove_method :original_decode
      end
    end
  end
end
