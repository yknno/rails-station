module Oidc
  class BackchannelLogoutProcessor
    class << self
      def process(token, oidc)
        decoded_token = Oidc::LogoutTokenDecoder.decode(token, oidc)
        jti = decoded_token["jti"]

        # jti を使用したリプレイ攻撃防止
        if LoggedOutJti.exists?(jti: jti)
          raise ReplayAttackError, "Backchannel logout validation failed: replayed jti #{jti}"
        end

        # トークンの exp から有効期限を算出し、未設定の場合はデフォルトで 24 時間に設定
        token_expires_at = decoded_token["exp"].present? ? Time.at(decoded_token["exp"]) : 24.hours.from_now

        # リプレイ攻撃防止のために JTI をデータベースに記録（ユニーク制約の競合は例外捕捉でハンドリング）
        begin
          LoggedOutJti.create!(jti: jti, expires_at: token_expires_at)
        rescue ActiveRecord::RecordNotUnique
          raise ReplayAttackError, "Backchannel logout validation failed: replayed jti #{jti} (race condition)"
        end

        sid = decoded_token["sid"]
        sub = decoded_token["sub"]

        if sid.present?
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
