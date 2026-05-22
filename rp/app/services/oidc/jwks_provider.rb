require "net/http"

module Oidc
  # OP から公開されている JWKS (JSON Web Key Set) の取得とキャッシュを管理するサービス
  # 参照: RFC 7517 (JSON Web Key - JWK) Section 5 (JWK Set Document)
  class JwksProvider
    # ハング防止のためのタイムアウト設定 (ベストプラクティス)
    HTTP_OPEN_TIMEOUT = 5
    HTTP_READ_TIMEOUT = 5

    class << self
      # JWKS をフェッチしキャッシュする
      # 
      # - 不正な `kid` による連続した再フェッチ要求（過負荷）を防ぐため、
      #   `force: true` による強制リフレッシュには 1 分間のレートリミットを適用します。
      # - 一時的なネットワーク障害等で JWKS 取得に失敗した場合に nil がキャッシュされるのを防ぐため、
      #   `skip_nil: true` を指定し、取得成功時のみキャッシュを更新します。
      def fetch_jwks(jwks_uri, force: false)
        if force
          # 強制リフレッシュに対してレートリミットを適用（最大で1分間に1回まで）
          last_fetched = Rails.cache.read("oidc_jwks_fetched_at")
          if last_fetched.nil? || last_fetched < 1.minute.ago
            Rails.cache.delete("oidc_jwks")
            Rails.cache.write("oidc_jwks_fetched_at", Time.current)
          else
            return Rails.cache.read("oidc_jwks")
          end
        end

        # 24時間キャッシュする。取得失敗時はキャッシュに書き込まない。
        Rails.cache.fetch("oidc_jwks", expires_in: 24.hours, skip_nil: true) do
          Rails.cache.write("oidc_jwks_fetched_at", Time.current)
          http_get_jwks(jwks_uri)
        end
      end

      # JWK Set オブジェクトを取得する
      def jwk_set(jwks_uri, force: false)
        jwks = fetch_jwks(jwks_uri, force: force)
        jwks ? JWT::JWK::Set.new(jwks) : nil
      end

      # 指定された kid が JWK Set 内に存在するか確認する
      def kid_in_set?(kid, set)
        return false if set.nil?
        set.any? { |jwk| jwk.kid == kid }
      end

      # JWKS エンドポイントへ HTTP GET し、パース済みの Hash を返す。
      # 失敗時は nil（呼び出し側はこの nil をキャッシュしないこと）。
      # 応答遅延による Web サーバスレッドの枯渇を防ぐため、タイムアウトを必ず明示する。
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
