class ApplicationController < ActionController::Base
  # Only allow modern browsers supporting webp images, web push, badges, import maps, CSS nesting, and CSS :has.
  allow_browser versions: :modern

  before_action :check_revoked_session

  private

  def check_revoked_session
    if session[:sid] && RevokedSession.exists?(sid: session[:sid])
      reset_session
      redirect_to root_path, alert: "Your session has been terminated by the identity provider."
    elsif session[:user_email] && RevokedSession.exists?(sid: "sub:#{session[:user_email]}")
      reset_session
      redirect_to root_path, alert: "Your session has been terminated by the identity provider."
    end
  end
end
