class ApplicationController < ActionController::Base
  # Only allow modern browsers supporting webp images, web push, badges, import maps, CSS nesting, and CSS :has.
  allow_browser versions: :modern

  protected

  def after_sign_in_path_for(resource)
    challenge = session.delete(:login_challenge)
    if challenge.present?
      new_login_path(login_challenge: challenge)
    else
      super
    end
  end
end
