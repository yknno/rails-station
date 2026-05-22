module Oidc
  # OP から送信された Logout Token をもとに、RP 側のアクティブセッションを特定・破棄するサービス
  # 参照: OpenID Connect Back-Channel Logout 1.0 Section 2.5 (Back-Channel Logout Request)
  class BackchannelLogoutProcessor
    class << self
      # バックチャネルログアウト処理の実行
      def process(token, oidc)
        # Logout Token のデコードと各種クレームの厳格な検証 (Section 2.4 Logout Token Validation)
        decoded_token = Oidc::LogoutTokenDecoder.decode(token, oidc)
        jti = decoded_token["jti"]

        # jti を使用したリプレイ攻撃防止 (Section 2.4, Item 9: The RP MUST validate the jti claim)
        # 一度処理したログアウト要求の再利用（リプレイ）をデータベースで検知して弾く
        if LoggedOutJti.exists?(jti: jti)
          raise ReplayAttackError, "Backchannel logout validation failed: replayed jti #{jti}"
        end

        # トークンの exp から有効期限を算出し、未設定の場合はデフォルトで 24 時間に設定
        # (失効したトークンをデータベースから後続のバッチ処理等で削除できるようにするため)
        token_expires_at = decoded_token["exp"].present? ? Time.at(decoded_token["exp"]) : 24.hours.from_now

        # リプレイ攻撃防止のために JTI をデータベースに記録
        # 同一 jti を持つログアウトがミリ秒単位で複数リクエストされた場合（同時実行競合）を考慮し、
        # DB のユニーク制約エラー (ActiveRecord::RecordNotUnique) を捕捉して ReplayAttackError とする。
        begin
          LoggedOutJti.create!(jti: jti, expires_at: token_expires_at)
        rescue ActiveRecord::RecordNotUnique
          raise ReplayAttackError, "Backchannel logout validation failed: replayed jti #{jti} (race condition)"
        end

        sid = decoded_token["sid"]
        sub = decoded_token["sub"]

        # ターゲットとなるユーザーセッションの特定と破棄 (Section 2.5: MUST terminate sessions matching sid and sub)
        # 1. sid と sub の両方がある場合: そのセッションを特定して削除
        # 2. sid のみの場合: 特定のブラウザセッション (Hydra Session ID) のみ削除
        # 3. sub のみの場合: そのユーザーに関連づけられた全デバイスのセッションをすべて削除 (シングルサインアウト)
        if sid.present? && sub.present?
          ActiveSession.joins(:account).where(sid: sid, accounts: { sub: sub }).destroy_all
          Rails.logger.info "Backchannel logout success: terminated active session sid #{sid} and sub #{sub}"
        elsif sid.present?
          ActiveSession.where(sid: sid).destroy_all
          Rails.logger.info "Backchannel logout success: terminated active session sid #{sid}"
        elsif sub.present?
          account = Account.find_by(sub: sub)
          if account
            account.active_sessions.destroy_all
            Rails.logger.info "Backchannel logout success: terminated active sessions for sub #{sub}"
          else
            Rails.logger.info "Backchannel logout: no account found for sub #{sub}"
          end
        end
      end
    end
  end
end
