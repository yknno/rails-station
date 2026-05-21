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
    @jwks_uri = "http://localhost:4444/jwks"
  end

  test "fetch_jwks fetches and caches JWKS" do
    cache_store = {}
    Rails.cache.stub(:fetch, ->(key, options = nil, &block) { cache_store[key] ||= block.call }) do
      Oidc::JwksProvider.stub(:http_get_jwks, @jwks_hash) do
        result1 = Oidc::JwksProvider.fetch_jwks(@jwks_uri)
        assert_equal @jwks_hash, result1
        assert_equal @jwks_hash, cache_store["oidc_jwks"]
      end
    end
  end

  test "fetch_jwks caches a successful response so the endpoint is hit only once" do
    call_count = 0
    Rails.stub(:cache, ActiveSupport::Cache::MemoryStore.new) do
      Oidc::JwksProvider.stub(:http_get_jwks, ->(_uri) { call_count += 1; @jwks_hash }) do
        assert_equal @jwks_hash, Oidc::JwksProvider.fetch_jwks(@jwks_uri)
        assert_equal @jwks_hash, Oidc::JwksProvider.fetch_jwks(@jwks_uri)
      end
    end
    assert_equal 1, call_count, "a successful JWKS response must be cached"
  end

  test "fetch_jwks does not cache nil when the JWKS endpoint fails" do
    call_count = 0
    Rails.stub(:cache, ActiveSupport::Cache::MemoryStore.new) do
      Oidc::JwksProvider.stub(:http_get_jwks, ->(_uri) { call_count += 1; nil }) do
        assert_nil Oidc::JwksProvider.fetch_jwks(@jwks_uri)
        assert_nil Oidc::JwksProvider.fetch_jwks(@jwks_uri)
      end
    end
    assert_equal 2, call_count, "a failed (nil) fetch must not be cached"
  end

  test "jwk_set returns JWT::JWK::Set when jwks fetched successfully" do
    Oidc::JwksProvider.stub(:http_get_jwks, @jwks_hash) do
      set = Oidc::JwksProvider.jwk_set(@jwks_uri)
      assert_instance_of JWT::JWK::Set, set
    end
  end

  test "jwk_set returns nil when JWKS cannot be fetched" do
    Oidc::JwksProvider.stub(:http_get_jwks, nil) do
      assert_nil Oidc::JwksProvider.jwk_set(@jwks_uri)
    end
  end

  test "kid_in_set? checks if kid is in the JWK set" do
    Oidc::JwksProvider.stub(:http_get_jwks, @jwks_hash) do
      set = Oidc::JwksProvider.jwk_set(@jwks_uri)
      assert Oidc::JwksProvider.kid_in_set?("key-1", set)
      assert_not Oidc::JwksProvider.kid_in_set?("key-2", set)
    end
  end
end
