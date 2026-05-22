# Ory Hydra と連携し、同意（認可）フローのビジネスロジックを管理するサービス
class ConsentFlowHandler
  attr_reader :challenge, :current_user, :hydra

  def initialize(challenge:, current_user:, hydra: OryHydraService.new)
    @challenge = challenge
    @current_user = current_user
    @hydra = hydra
  end

  # 新規同意要求の判定処理
  def handle_new
    if challenge.blank?
      return Result.error("Missing consent challenge.")
    end

    begin
      # Ory Hydra から同意要求の詳細情報を取得
      consent_request = hydra.get_consent_request(challenge)
    rescue => e
      return Result.error("Error communicating with Hydra: #{e.message}")
    end

    # 1. 同意画面のスキップ判定
    # 参照: Ory Hydra 仕様
    # - 過去に同一のクライアントに対して同じスコープの同意をユーザーが行っており、
    #   その同意が Hydra のセッションに残っている場合、`skip` が true となる
    # - この場合、同意画面を表示せず、要求されたスコープとオーディエンスで自動的に承諾応答を送る
    if consent_request["skip"]
      begin
        accept_response = hydra.accept_consent_request(
          challenge,
          consent_request["requested_scope"],
          consent_request["requested_access_token_audience"],
          current_user
        )
        return Result.redirect_to_hydra(accept_response["redirect_to"])
      rescue OryHydraService::Error => e
        return Result.error("Error communicating with Hydra: #{e.message}")
      rescue => e
        return Result.error("Error accepting consent request: #{e.message}")
      end
    end

    # 同意画面をレンダーするために詳細情報を返す
    Result.render_consent(consent_request)
  end

  # ユーザーが同意を承諾した場合の処理
  # 参照: Ory Hydra API /oauth2/auth/requests/consent/accept
  # - 認可要求時にクライアントから指定された scopes および audiences を引き継いで Hydra へ受諾を送信する
  def handle_accept
    begin
      # 元の認可リクエストからスコープとオーディエンスを取得
      consent_request = hydra.get_consent_request(challenge)
      
      accept_response = hydra.accept_consent_request(
        challenge,
        consent_request["requested_scope"],
        consent_request["requested_access_token_audience"],
        current_user
      )
      Result.redirect_to_hydra(accept_response["redirect_to"])
    rescue OryHydraService::Error => e
      Result.error("Error communicating with Hydra: #{e.message}")
    rescue => e
      Result.error("Error accepting consent request: #{e.message}")
    end
  end

  # ユーザーが同意を拒否した場合の処理
  # 参照: Ory Hydra API /oauth2/auth/requests/consent/reject
  # - Hydra 側へ拒否を通知。これを受けた Hydra は、OAuth 2.0 規格（RFC 6749 Section 4.1.2.1）に準拠した
  #   `access_denied` エラー応答を認可クライアントへ返却する。
  def handle_reject
    begin
      reject_response = hydra.reject_consent_request(challenge, "User denied consent.")
      Result.redirect_to_hydra(reject_response["redirect_to"])
    rescue => e
      Result.error("Error rejecting consent request: #{e.message}")
    end
  end

  class Result
    attr_reader :action, :redirect_to, :error_message, :consent_request

    def initialize(action:, redirect_to: nil, error_message: nil, consent_request: nil)
      @action = action
      @redirect_to = redirect_to
      @error_message = error_message
      @consent_request = consent_request
    end

    def self.redirect_to_hydra(url)
      new(action: :redirect_to_hydra, redirect_to: url)
    end

    def self.render_consent(request)
      new(action: :render_consent, consent_request: request)
    end

    def self.error(message)
      new(action: :error, error_message: message)
    end

    def success?
      action != :error
    end
  end
end
