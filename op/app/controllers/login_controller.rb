# Ory Hydra の User Login Flow (ユーザー認証) に対応する OP 側のコントローラ
# 参照: Ory Hydra User Login & Consent Flow Architecture
class LoginController < ApplicationController
  # Devise による全体認証制限をスキップし、独自のログインハンドラーで認証状態をコントロールする
  skip_before_action :authenticate_user!, raise: false

  # Ory Hydra からのログイン要求を受け付けるアクション
  # 参照:
  # - OIDC Core 1.0 Section 3.1.2.1 (Authentication Request) -> Hydra が仲介
  # - Ory Hydra Admin API /oauth2/auth/requests/login
  # 
  # 処理の流れ:
  # - Ory Hydra がブラウザをこのエンドポイントにリダイレクトし、クエリパラメータ `login_challenge` を渡す
  # - `login_challenge` はフローの状態を特定するための Ory 独自のセッショントークン
  # - ユーザーがすでにログイン済みの場合は自動承諾し、未ログインの場合は Devise ログイン画面へ遷移させる
  def new
    handler = LoginFlowHandler.new(
      challenge: params[:login_challenge],
      current_user: current_user,
      session: session
    )
    result = handler.handle_new

    if result.success?
      if result.action == :redirect_to_hydra
        # Hydra への自動承諾または受託完了に伴うリダイレクト（OIDC 認証結果の送信準備）
        redirect_to result.redirect_to, allow_other_host: true
      elsif result.action == :redirect_to_new_session
        # 未ログイン、または prompt=login 仕様により再認証が必要な場合
        # (OIDC Core 1.0 Section 3.1.2.1: prompt=login 時は既存の認証セッションを破棄して再認証させなければならない)
        sign_out(current_user) if result.force_sign_out && user_signed_in?
        redirect_to new_user_session_path
      end
    else
      redirect_to root_path, alert: result.error_message
    end
  end

  # ログイン処理を拒否・キャンセルする場合のアクション
  # 参照: Ory Hydra API /oauth2/auth/requests/login/reject
  # - 認証エラー（例: ユーザーがキャンセル）を Ory Hydra に通知し、クライアントへエラー応答を返すようにする
  def reject
    challenge = params[:login_challenge] || session.delete(:login_challenge)
    handler = LoginFlowHandler.new(
      challenge: challenge,
      current_user: current_user,
      session: session
    )
    result = handler.handle_reject

    if result.success?
      redirect_to result.redirect_to, allow_other_host: true
    else
      redirect_to root_path, alert: result.error_message
    end
  end
end
