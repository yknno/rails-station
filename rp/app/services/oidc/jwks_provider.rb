require "net/http"

module Oidc
  class JwksProvider
    HTTP_OPEN_TIMEOUT = 5
    HTTP_READ_TIMEOUT = 5

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

        # skip_nil: 取得失敗（nil）はキャッシュしない。これがないと一時的な
        # ネットワーク障害で nil が 24 時間キャッシュに居座り、その間 JWKS が
        # 一切引けなくなる。
        Rails.cache.fetch("oidc_jwks", expires_in: 24.hours, skip_nil: true) do
          Rails.cache.write("oidc_jwks_fetched_at", Time.current)
          http_get_jwks(jwks_uri)
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

      # JWKS エンドポイントへ HTTP GET し、パース済みの Hash を返す。
      # 失敗時は nil（呼び出し側はこの nil をキャッシュしないこと）。
      # ハングを防ぐため open/read タイムアウトを必ず設定する。
      def http_get_jwks(jwks_uri)
        uri = URI(jwks_uri)
        response = Net::HTTP.start(
          uri.host, uri.port,
          use_ssl: uri.scheme == "https",
          open_timeout: HTTP_OPEN_TIMEOUT,
          read_timeout: HTTP_READ_TIMEOUT
        ) { |http| http.get(uri.request_uri) }

        unless response.is_a?(Net::HTTPSuccess)
          Rails.logger.error "Failed to fetch JWKS from #{jwks_uri}: HTTP #{response.code}"
          return nil
        end

        JSON.parse(response.body)
      rescue => e
        Rails.logger.error "Failed to fetch JWKS from #{jwks_uri}: #{e.message}"
        nil
      end
    end
  end
end
