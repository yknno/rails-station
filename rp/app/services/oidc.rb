module Oidc
  class JwksUnavailableError < StandardError; end
  class TokenValidationError < JWT::DecodeError; end
  class ReplayAttackError < TokenValidationError; end
end
