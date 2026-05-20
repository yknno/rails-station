class HomeController < ApplicationController
  def index
    @user_email = session[:user_email]
    @id_token_claims = session[:id_token]
  end
end
