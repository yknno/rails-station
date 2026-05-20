require "test_helper"

class OidcServiceTest < ActiveSupport::TestCase
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
  end

  test "fetch_jwks fetches and caches JWKS" do
    cache_store = {}
    Rails.cache.stub(:fetch, ->(key, options = nil, &block) { cache_store[key] ||= block.call }) do
      Net::HTTP.stub(:get, @jwks_json) do
        result1 = OidcService.fetch_jwks
        assert_equal @jwks_hash, result1
        assert_equal @jwks_hash, cache_store["oidc_jwks"]
      end
    end
  end

  test "decode_and_verify uses JWKS and decodes token successfully" do
    claims = { "iss" => "http://localhost:4444/", "aud" => "rp-client", "sub" => "123", "iat" => Time.now.to_i }
    Net::HTTP.stub(:get, @jwks_json) do
      JWT::JWK::Set.stub(:new, Object.new) do
        JWT.stub(:decode, [claims, { "alg" => "RS256" }]) do
          decoded = OidcService.decode_and_verify("mock-token")
          assert_equal claims, decoded
        end
      end
    end
  end

  test "decode_and_verify forces JWKS refresh when token kid is missing from cached JWKS" do
    cache_store = {}
    # Seed cache with old JWKS (key-1)
    cache_store["oidc_jwks"] = @jwks_hash
    # Assume it was fetched 10 minutes ago
    cache_store["oidc_jwks_fetched_at"] = 10.minutes.ago

    new_jwks_hash = {
      "keys" => [
        {
          "kty" => "RSA",
          "kid" => "key-2", # New key
          "use" => "sig",
          "alg" => "RS256",
          "n" => "new-mock-n",
          "e" => "AQAB"
        }
      ]
    }
    new_jwks_json = new_jwks_hash.to_json

    claims = { "iss" => "http://localhost:4444/", "aud" => "rp-client", "sub" => "123", "iat" => Time.now.to_i }

    # Setup stubs for Rails.cache, Net::HTTP.get, and JWT.decode
    Rails.cache.stub(:read, ->(key) { cache_store[key] }) do
      Rails.cache.stub(:write, ->(key, val, options = nil) { cache_store[key] = val }) do
        Rails.cache.stub(:delete, ->(key) { cache_store.delete(key) }) do
          Rails.cache.stub(:fetch, ->(key, options = nil, &block) { cache_store[key] ||= block.call }) do
            Net::HTTP.stub(:get, new_jwks_json) do
              JWT::JWK::Set.stub(:new, Object.new) do
                # Stub decode to return parsed headers containing new kid "key-2"
                JWT.stub(:decode, ->(*args) {
                  verify = args[2]
                  if verify
                    [claims, { "alg" => "RS256", "kid" => "key-2" }]
                  else
                    [claims, { "alg" => "RS256", "kid" => "key-2" }]
                  end
                }) do
                  decoded = OidcService.decode_and_verify("mock-token-with-new-kid")
                  assert_equal claims, decoded
                  # Confirm the cache was updated with the new JWKS
                  assert_equal new_jwks_hash, cache_store["oidc_jwks"]
                end
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
    # Set fetched_at to 30 seconds ago (rate limited since < 1 minute)
    cache_store["oidc_jwks_fetched_at"] = 30.seconds.ago

    claims = { "iss" => "http://localhost:4444/", "aud" => "rp-client", "sub" => "123", "iat" => Time.now.to_i }

    get_called = false
    Rails.cache.stub(:read, ->(key) { cache_store[key] }) do
      Rails.cache.stub(:write, ->(key, val, options = nil) { cache_store[key] = val }) do
        Rails.cache.stub(:fetch, ->(key, options = nil, &block) { cache_store[key] ||= block.call }) do
          Net::HTTP.stub(:get, ->(uri) { get_called = true; @jwks_json }) do
            JWT::JWK::Set.stub(:new, Object.new) do
              JWT.stub(:decode, ->(*args) {
                verify = args[2]
                if verify
                  [claims, { "alg" => "RS256", "kid" => "key-2" }]
                else
                  [claims, { "alg" => "RS256", "kid" => "key-2" }]
                end
              }) do
                decoded = OidcService.decode_and_verify("mock-token-with-new-kid")
                assert_equal claims, decoded
                # Net::HTTP.get should not have been called because of the rate limit
                assert_not get_called
              end
            end
          end
        end
      end
    end
  end
end
