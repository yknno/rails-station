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
      # セキュリティ対策 (DoS・過負荷防止):
      # - 不正な `kid` を含んだ JWT トークンを大量に送りつけられると、キャッシュミスが発生し
      #   JWKS の再フェッチ処理が連続で発生して OP および RP の過負荷（DoS）を引き起こす可能性がある。
      #   そのため、`force: true` による強制リフレッシュ要求には 1 分間のレートリミットを課す。
      #
      # 可用性対策 (skip_nil):
      # - 一時的なネットワーク障害によって JWKS の取得に失敗（nil が返却）した場合、
      #   その `nil` をキャッシュしてしまうと、キャッシュの有効期間（24時間）の間、
      #   トークン検証が一切行えなくなる。これを防ぐため `skip_nil: true` を設定し、
      #   取得成功時のみキャッシュに書き込む。
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

        # 24時間キャッシュする。取得失敗時はキャッシュしない設計
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
