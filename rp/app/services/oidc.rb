module Oidc
  class JwksUnavailableError < StandardError; end
  class ValidationError < JWT::DecodeError; end
  class ReplayAttackError < ValidationError; end
end
