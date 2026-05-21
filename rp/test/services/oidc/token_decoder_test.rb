require "test_helper"

class Oidc::TokenDecoderTest < ActiveSupport::TestCase
  setup do
    @jwks_hash = {
      "keys" => [
        {
          "kty" => "RSA",
          "kid" => "key-1",
          "use" => "sig",
          "alg" => "RS256",
          "n" => "mock-n",
          "e" => "AQAB"
        }
      ]
    }
    @jwks_json = @jwks_hash.to_json
    @jwks_uri = "http://localhost:4444/jwks"
  end

  test "decode_and_verify uses JWKS and decodes token successfully" do
    claims = { "iss" => "http://localhost:4444/", "aud" => "rp-client", "sub" => "123", "iat" => Time.now.to_i }
    Net::HTTP.stub(:get, @jwks_json) do
      JWT.stub(:decode, [claims, { "alg" => "RS256" }]) do
        decoded = Oidc::TokenDecoder.decode_and_verify("mock-token", @jwks_uri)
        assert_equal claims, decoded
      end
    end
  end

  test "decode_and_verify raises JwksUnavailableError when JWKS cannot be retrieved" do
    Net::HTTP.stub(:get, ->(_uri) { raise StandardError, "network error" }) do
      assert_raises Oidc::JwksUnavailableError do
        Oidc::TokenDecoder.decode_and_verify("mock-token", @jwks_uri)
      end
    end
  end

  test "decode_and_verify forces JWKS refresh when token kid is missing from cached JWKS" do
    cache_store = {}
    cache_store["oidc_jwks"] = @jwks_hash
    cache_store["oidc_jwks_fetched_at"] = 10.minutes.ago

    new_jwks_hash = {
      "keys" => [
        {
          "kty" => "RSA",
          "kid" => "key-2",
          "use" => "sig",
          "alg" => "RS256",
          "n" => "new-mock-n",
          "e" => "AQAB"
        }
      ]
    }
    new_jwks_json = new_jwks_hash.to_json
    claims = { "iss" => "http://localhost:4444/", "aud" => "rp-client", "sub" => "123", "iat" => Time.now.to_i }

    Rails.cache.stub(:read, ->(key) { cache_store[key] }) do
      Rails.cache.stub(:write, ->(key, val, options = nil) { cache_store[key] = val }) do
        Rails.cache.stub(:delete, ->(key) { cache_store.delete(key) }) do
          Rails.cache.stub(:fetch, ->(key, options = nil, &block) { cache_store[key] ||= block.call }) do
            Net::HTTP.stub(:get, new_jwks_json) do
              JWT.stub(:decode, ->(*args) {
                [claims, { "alg" => "RS256", "kid" => "key-2" }]
              }) do
                decoded = Oidc::TokenDecoder.decode_and_verify("mock-token-with-new-kid", @jwks_uri)
                assert_equal claims, decoded
                assert_equal new_jwks_hash, cache_store["oidc_jwks"]
              end
            end
          end
        end
      end
    end
  end

  test "decode_and_verify does not refresh JWKS when rate limited" do
    cache_store = {}
    cache_store["oidc_jwks"] = @jwks_hash
    cache_store["oidc_jwks_fetched_at"] = 30.seconds.ago

    claims = { "iss" => "http://localhost:4444/", "aud" => "rp-client", "sub" => "123", "iat" => Time.now.to_i }
    get_called = false

    Rails.cache.stub(:read, ->(key) { cache_store[key] }) do
      Rails.cache.stub(:write, ->(key, val, options = nil) { cache_store[key] = val }) do
        Rails.cache.stub(:fetch, ->(key, options = nil, &block) { cache_store[key] ||= block.call }) do
          Net::HTTP.stub(:get, ->(uri) { get_called = true; @jwks_json }) do
            JWT.stub(:decode, ->(*args) {
              [claims, { "alg" => "RS256", "kid" => "key-2" }]
            }) do
              decoded = Oidc::TokenDecoder.decode_and_verify("mock-token-with-new-kid", @jwks_uri)
              assert_equal claims, decoded
              assert_not get_called
            end
          end
        end
      end
    end
  end
end
