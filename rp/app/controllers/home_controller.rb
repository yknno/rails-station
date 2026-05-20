class HomeController < ApplicationController
  def index
    if current_active_session
      @user_email = current_active_session.user_email
      @id_token_claims = current_active_session.claims
    end
  end
end
