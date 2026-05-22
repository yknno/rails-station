# Ory Hydra の User Logout Flow (ログアウト処理) に対応する OP 側のコントローラ
# 参照: Ory Hydra User Login & Consent Flow Architecture
class LogoutController < ApplicationController
  # セッションがすでに失われている場合でもログアウト完了画面にリダイレクトできるようにするため、
  # Devise によるログイン必須フィルター (authenticate_user!) をスキップし、手動でサインアウト処理を制御する。
  
  # Ory Hydra からのログアウト要求を受け付けるアクション
  # 参照:
  # - OpenID Connect RP-Initiated Logout 1.0 Section 2 (RP-Initiated Logout Endpoint) -> Hydra が仲介
  # - Ory Hydra Admin API /oauth2/auth/requests/logout
  # 
  # 処理の流れ:
  # - RP等からログアウトが要求され、Ory Hydra はブラウザをこのエンドポイントへ `logout_challenge` を付与してリダイレクトする
  # - `logout_challenge` はログアウトの状態を特定するための Ory 独自のセッショントークン
  # - Hydra 側のログアウト要求を承諾 (accept_logout_request) し、さらに本 OP 側のローカルセッション（Devise）も削除する
  # - 最後に Hydra から返されるリダイレクト URL（RP のリダイレクト先など）へブラウザを転送する
  def new
    challenge = params[:logout_challenge]
    if challenge.blank?
      redirect_to root_path, alert: "Missing logout challenge."
      return
    end

    hydra = OryHydraService.new
    begin
      accept_response = hydra.accept_logout_request(challenge)
      
      # OP 側 (Devise) のローカルセッションを破棄
      sign_out(current_user) if user_signed_in?
      
      # Hydra が生成した最終リダイレクト先 (通常は RP の post_logout_redirect_uri など) へ遷移
      redirect_to accept_response["redirect_to"], allow_other_host: true
    rescue => e
      redirect_to root_path, alert: "Error accepting logout request: #{e.message}"
    end
  end
end
