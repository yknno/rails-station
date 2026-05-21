require "test_helper"

class Oidc::IdTokenDecoderTest < ActiveSupport::TestCase
  setup do
    @jwks_hash = { "keys" => [] }
    @jwks_json = @jwks_hash.to_json
    @jwks_uri = "http://localhost:4444/jwks"
    oidc_class = Struct.new(:issuer, :client_id, :jwks_uri)
    @oidc_config = oidc_class.new(
      "http://localhost:4444/",
      "rp-client",
      @jwks_uri
    )
  end

  test "decode decodes and validates ID token claims" do
    claims = {
      "iss" => "http://localhost:4444/",
      "aud" => "rp-client",
      "sub" => "123",
      "exp" => Time.now.to_i + 3600,
      "iat" => Time.now.to_i
    }
    Net::HTTP.stub(:get, @jwks_json) do
      JWT.stub(:decode, [claims, { "alg" => "RS256" }]) do
        decoded = Oidc::IdTokenDecoder.decode("mock-id-token", @oidc_config)
        assert_equal claims, decoded
      end
    end
  end
end
