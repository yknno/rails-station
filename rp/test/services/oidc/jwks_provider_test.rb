require "test_helper"

class Oidc::JwksProviderTest < ActiveSupport::TestCase
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

  test "fetch_jwks fetches and caches JWKS" do
    cache_store = {}
    Rails.cache.stub(:fetch, ->(key, options = nil, &block) { cache_store[key] ||= block.call }) do
      Net::HTTP.stub(:get, @jwks_json) do
        result1 = Oidc::JwksProvider.fetch_jwks(@jwks_uri)
        assert_equal @jwks_hash, result1
        assert_equal @jwks_hash, cache_store["oidc_jwks"]
      end
    end
  end

  test "jwk_set returns JWT::JWK::Set when jwks fetched successfully" do
    Net::HTTP.stub(:get, @jwks_json) do
      set = Oidc::JwksProvider.jwk_set(@jwks_uri)
      assert_instance_of JWT::JWK::Set, set
    end
  end

  test "kid_in_set? checks if kid is in the JWK set" do
    Net::HTTP.stub(:get, @jwks_json) do
      set = Oidc::JwksProvider.jwk_set(@jwks_uri)
      assert Oidc::JwksProvider.kid_in_set?("key-1", set)
      assert_not Oidc::JwksProvider.kid_in_set?("key-2", set)
    end
  end
end
