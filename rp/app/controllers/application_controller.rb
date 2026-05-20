class ApplicationController < ActionController::Base
  # Only allow modern browsers supporting webp images, web push, badges, import maps, CSS nesting, and CSS :has.
  allow_browser versions: :modern

  before_action :load_active_session
  helper_method :current_active_session

  def current_active_session
    if session[:active_session_id].present?
      @current_active_session ||= ActiveSession.find_by(id: session[:active_session_id])
    else
      nil
    end
  end

  def reset_session
    super
    @current_active_session = nil
  end

  private

  def load_active_session
    if session[:active_session_id].present?
      session_record = current_active_session
      if session_record.nil? || session_record.expired?
        session_record&.destroy
        reset_session
        redirect_to root_path, alert: "Your session has expired or has been terminated by the identity provider."
      end
    end
  end
end
