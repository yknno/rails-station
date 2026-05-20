class HomeController < ApplicationController
  def index
    Rails.logger.debug "=== HomeController Session: #{session.to_hash.inspect} ==="
    @user_email = session[:user_email]
    
    if session[:raw_id_token].present?
      begin
        @id_token_claims = JWT.decode(session[:raw_id_token], nil, false).first
      rescue => e
        Rails.logger.warn "Failed to decode raw ID token: #{e.message}"
        @id_token_claims = nil
      end
    end
  end
end
