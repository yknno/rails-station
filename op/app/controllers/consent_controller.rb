# Ory Hydra の User Consent Flow (認可・同意処理) に対応する OP 側のコントローラ
# 参照: Ory Hydra User Login & Consent Flow Architecture
class ConsentController < ApplicationController
  # 同意（認可）を与えるためには、ユーザーが本 OP 上でログイン（認証）済みである必要がある
  # 参照: OIDC Core 1.0 Section 3.1.2.4 (Consent)
  before_action :authenticate_user!

  # Ory Hydra からの同意要求を受け付けるアクション
  # 参照:
  # - OIDC Core 1.0 Section 3.1.2.4 (Consent) / OAuth 2.0 (RFC 6749) Section 4.1.1
  # - Ory Hydra Admin API /oauth2/auth/requests/consent
  # 
  # 処理の流れ:
  # - ログイン成功後、Ory Hydra から `consent_challenge` パラメータとともにリダイレクトされる
  # - `consent_challenge` は同意リクエストの状態を識別するための Ory 独自のセッショントークン
  # - 以前に同意した履歴がある等の理由で Hydra が skip: true を提示してきた場合、同意画面を表示せず自動承諾する
  # - 同意画面が必要な場合は、クライアント情報、要求スコープ、オーディエンスをビューに渡す
  def new
    @challenge = params[:consent_challenge]
    handler = ConsentFlowHandler.new(challenge: @challenge, current_user: current_user)
    result = handler.handle_new

    if result.success?
      if result.action == :redirect_to_hydra
        # 同意スキップ（自動承諾）による Hydra へのリダイレクト
        redirect_to result.redirect_to, allow_other_host: true
      elsif result.action == :render_consent
        # 同意確認画面の表示用パラメータ設定
        @consent_request = result.consent_request
        @client = @consent_request["client"]
        @requested_scope = @consent_request["requested_scope"]
        @requested_audience = @consent_request["requested_access_token_audience"]
      end
    else
      redirect_to root_path, alert: result.error_message
    end
  end

  # 同意確認画面からの POST アクション
  # - ユーザーの意思（承諾: accept / 拒否: reject）に応じて Hydra Admin API へ意思を送信し、結果のリダイレクト先へ転送する
  def create
    challenge = params[:consent_challenge]
    handler = ConsentFlowHandler.new(challenge: challenge, current_user: current_user)

    result = if params[:submit] == "accept"
               handler.handle_accept
             else
               handler.handle_reject
             end

    if result.success?
      redirect_to result.redirect_to, allow_other_host: true
    else
      redirect_to root_path, alert: result.error_message
    end
  end
end
