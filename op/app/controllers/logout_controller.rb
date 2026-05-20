class LogoutController < ApplicationController
  # Skip authenticate_user! because we want to allow logout even if session is already gone or needs sign out.
  # We manually sign out if they are signed in.
  
  def new
    challenge = params[:logout_challenge]
    if challenge.blank?
      redirect_to root_path, alert: "Missing logout challenge."
      return
    end

    hydra = OryHydraService.new
    begin
      accept_response = hydra.accept_logout_request(challenge)
      
      # Terminate Devise session locally on the OP
      sign_out(current_user) if user_signed_in?
      
      redirect_to accept_response["redirect_to"], allow_other_host: true
    rescue => e
      redirect_to root_path, alert: "Error accepting logout request: #{e.message}"
    end
  end
end
