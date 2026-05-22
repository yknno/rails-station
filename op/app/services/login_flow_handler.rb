# Ory Hydra と連携し、ログインフロー（ユーザー認証の検証および受諾・拒否）のビジネスロジックを管理するサービス
class LoginFlowHandler
  attr_reader :challenge, :current_user, :session, :hydra

  def initialize(challenge:, current_user:, session:, hydra: OryHydraService.new)
    @challenge = challenge
    @current_user = current_user
    @session = session
    @hydra = hydra
  end

  # 新規ログイン要求の判定処理
  def handle_new
    if challenge.blank?
      return Result.error("Missing login challenge.")
    end

    begin
      # Ory Hydra Admin API からログイン要求の詳細情報を取得
      login_request = hydra.get_login_request(challenge)
    rescue => e
      return Result.error("Error communicating with Hydra: #{e.message}")
    end

    # 1. prompt=login 要求時の強制再認証 (仕様への準拠)
    # 参照: OIDC Core 1.0 Section 3.1.2.1 (Authentication Request) の prompt パラメータ仕様:
    # - `prompt` に `login` が指定されている場合、OP はエンドユーザーの再認証を行う「べきである (MUST)」
    # - ただし、同一の `challenge` に対して何度もサインアウトさせると無限ループになるため、
    #   未適用の場合のみ `force_sign_out: true` で Devise ログイン画面へ強制遷移させる
    if login_request.prompt_login? && session[:prompt_login_triggered_for] != challenge
      session[:prompt_login_triggered_for] = challenge
      session[:login_challenge] = challenge
      return Result.redirect_to_new_session(force_sign_out: true)
    end

    # 2. Ory Hydra のセッションによる自動スキップ判定
    # 参照: Ory Hydra 仕様
    # - ユーザーが過去にログインし、Hydra 側に有効なセッションがある場合は `skip: true` となる
    # - この場合、ログインUIを表示せずに以前のユーザー識別子 (`subject`) で自動承諾する
    if login_request.skip?
      begin
        accept_response = hydra.accept_login_request(challenge, login_request.subject)
        return Result.redirect_to_hydra(accept_response["redirect_to"])
      rescue => e
        return Result.error("Error accepting login request: #{e.message}")
      end
    end

    # 3. Railsアプリ（OP）側でログイン済みの判定
    # - ユーザーが Rails アプリ（Devise）にすでにログインしている場合、そのユーザー ID を subject として Hydra に通知し、ログインを承諾する
    if current_user.present?
      begin
        accept_response = hydra.accept_login_request(challenge, current_user.id.to_s)
        return Result.redirect_to_hydra(accept_response["redirect_to"])
      rescue OryHydraService::Error => e
        return Result.error("Error communicating with Hydra: #{e.message}")
      rescue => e
        return Result.error("Error accepting login request: #{e.message}")
      end
    end

    # 4. 未認証の場合
    # - challenge をセッションに一時保存し、Devise のログイン画面へ遷移させる
    session[:login_challenge] = challenge
    Result.redirect_to_new_session(force_sign_out: false)
  end

  # ログイン拒否処理
  # 参照: Ory Hydra API /oauth2/auth/requests/login/reject
  # - ユーザーが認証をキャンセルした場合に呼び出され、Hydra 経由でクライアントにエラーを通知する
  def handle_reject
    if challenge.blank?
      return Result.error("Missing login challenge.")
    end

    begin
      reject_response = hydra.reject_login_request(challenge, "User cancelled login.")
      session.delete(:login_challenge)
      Result.redirect_to_hydra(reject_response["redirect_to"])
    rescue OryHydraService::Error => e
      Result.error("Error communicating with Hydra: #{e.message}")
    rescue => e
      Result.error("Error rejecting login request: #{e.message}")
    end
  end

  class Result
    attr_reader :action, :redirect_to, :error_message, :force_sign_out

    def initialize(action:, redirect_to: nil, error_message: nil, force_sign_out: false)
      @action = action
      @redirect_to = redirect_to
      @error_message = error_message
      @force_sign_out = force_sign_out
    end

    def self.redirect_to_hydra(url)
      new(action: :redirect_to_hydra, redirect_to: url)
    end

    def self.redirect_to_new_session(force_sign_out:)
      new(action: :redirect_to_new_session, force_sign_out: force_sign_out)
    end

    def self.error(message)
      new(action: :error, error_message: message)
    end

    def success?
      action != :error
    end
  end
end
