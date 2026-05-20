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

  def after_sign_out_path_for(resource_or_scope)
    hydra_public_url = ENV.fetch("HYDRA_PUBLIC_URL") { "http://localhost:4444" }
    "#{hydra_public_url}/oauth2/sessions/logout"
  end
end
