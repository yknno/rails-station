class ApplicationController < ActionController::Base
  # Only allow modern browsers supporting webp images, web push, badges, import maps, CSS nesting, and CSS :has.
  allow_browser versions: :modern

  before_action :load_active_session
  helper_method :current_active_session

  def current_active_session
    @current_active_session ||= ActiveSession.find_by(id: session[:active_session_id]) if session[:active_session_id]
  end

  private

  def load_active_session
    # If session is active in cookie but not in DB (deleted via Backchannel Logout), reset session
    if session[:active_session_id].present? && current_active_session.nil?
      reset_session
      redirect_to root_path, alert: "Your session has been terminated by the identity provider."
    end
  end
end
