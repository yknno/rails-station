class OryHydraService
  # Ory Hydra から返却される Login Request 情報をラップし、判定ロジックを提供するクラス
  class LoginRequest
    attr_reader :raw

    def initialize(raw)
      @raw = raw || {}
    end

    # Hydra 側でのログイン確認画面をスキップ（自動承諾）可能であるか判定する
    # 参照: Ory Hydra 仕様
    def skip?
      raw["skip"] == true
    end

    # ログイン中のユーザーID (subject)
    def subject
      raw["subject"]
    end

    # 元の OAuth2/OIDC 認可リクエストの URL
    def request_url
      raw["request_url"]
    end

    # 認可リクエストに prompt=login が指定され、ユーザーの再認証が必要であるか判定する
    # 参照: OIDC Core 1.0 Section 3.1.2.1 (Authentication Request) の prompt パラメータ仕様
    # 
    # 解析ロジック:
    # - `request_url` 内のクエリパラメータから `prompt` キーの値を取り出す
    # - `prompt` パラメータはスペース区切りの文字列（例: "consent login"）で表現される可能性がある
    #   そのため、`split(/\s+/)` で分割した配列の中に "login" が含まれているか確認する
    def prompt_login?
      return false if request_url.blank?

      begin
        uri = URI.parse(request_url)
        params_hash = Rack::Utils.parse_query(uri.query || "")
        prompt_param = params_hash["prompt"]
        prompt_param.to_s.split(/\s+/).include?("login")
      rescue => e
        Rails.logger.error "Failed to parse prompt parameter from request_url: #{e.message}"
        false
      end
    end
  end
end
