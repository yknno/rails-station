module Oidc
  class IdTokenDecoder
    class << self
      def decode(token, oidc)
        Oidc::TokenDecoder.decode_and_verify(token, oidc.jwks_uri, {
          aud: oidc.client_id,
          verify_aud: true,
          iss: oidc.issuer,
          verify_iss: true
        })
      end
    end
  end
end
