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
end
