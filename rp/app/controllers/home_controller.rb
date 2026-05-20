class HomeController < ApplicationController
  def index
    if current_active_session
      @user_email = current_active_session.user_email
      if current_active_session.raw_id_token.present?
        begin
          @id_token_claims = JWT.decode(current_active_session.raw_id_token, nil, false).first
        rescue => e
          Rails.logger.warn "Failed to decode raw ID token: #{e.message}"
          @id_token_claims = nil
        end
      end
    end
  end
end
