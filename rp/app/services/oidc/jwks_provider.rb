module Oidc
  class JwksProvider
    class << self
      def fetch_jwks(jwks_uri, force: false)
        if force
          # DoS攻撃を防ぐため、強制リフレッシュに対してレートリミットを適用（最大で1分間に1回まで）
          last_fetched = Rails.cache.read("oidc_jwks_fetched_at")
          if last_fetched.nil? || last_fetched < 1.minute.ago
            Rails.cache.delete("oidc_jwks")
            Rails.cache.write("oidc_jwks_fetched_at", Time.current)
          else
            return Rails.cache.read("oidc_jwks")
          end
        end

        Rails.cache.fetch("oidc_jwks", expires_in: 24.hours) do
          Rails.cache.write("oidc_jwks_fetched_at", Time.current)
          begin
            jwks_response = Net::HTTP.get(URI(jwks_uri))
            JSON.parse(jwks_response)
          rescue => e
            Rails.logger.error "Failed to fetch JWKS from #{jwks_uri}: #{e.message}"
            nil
          end
        end
      end

      def jwk_set(jwks_uri, force: false)
        jwks = fetch_jwks(jwks_uri, force: force)
        jwks ? JWT::JWK::Set.new(jwks) : nil
      end

      def kid_in_set?(kid, set)
        return false if set.nil?
        set.any? { |jwk| jwk.kid == kid }
      end
    end
  end
end
