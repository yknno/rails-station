class LoginController < ApplicationController
  # We don't want to authenticate_user! globally here, we handle it custom
  skip_before_action :authenticate_user!, raise: false

  def new
    challenge = params[:login_challenge]
    if challenge.blank?
      redirect_to root_path, alert: "Missing login challenge."
      return
    end

    hydra = OryHydraService.new
    begin
      login_request = hydra.get_login_request(challenge)
    rescue => e
      redirect_to root_path, alert: "Error communicating with Hydra: #{e.message}"
      return
    end

    # If hydra says we should skip (session exists in Hydra)
    if login_request["skip"]
      begin
        accept_response = hydra.accept_login_request(challenge, login_request["subject"])
        redirect_to accept_response["redirect_to"], allow_other_host: true
      rescue => e
        redirect_to root_path, alert: "Error accepting login request: #{e.message}"
      end
      return
    end

    # If user is already signed in on our Rails application
    if user_signed_in?
      begin
        accept_response = hydra.accept_login_request(challenge, current_user.id.to_s)
        redirect_to accept_response["redirect_to"], allow_other_host: true
      rescue OryHydraService::Error => e
        redirect_to root_path, alert: "Error communicating with Hydra: #{e.message}"
      rescue => e
        redirect_to root_path, alert: "Error accepting login request: #{e.message}"
      end
      return
    end

    # Otherwise, store challenge in session and redirect to Devise sign-in
    session[:login_challenge] = challenge
    redirect_to new_user_session_path
  end

  def reject
    challenge = params[:login_challenge] || session.delete(:login_challenge)
    if challenge.blank?
      redirect_to root_path, alert: "Missing login challenge."
      return
    end

    hydra = OryHydraService.new
    begin
      reject_response = hydra.reject_login_request(challenge, "User cancelled login.")
      session.delete(:login_challenge)
      redirect_to reject_response["redirect_to"], allow_other_host: true
    rescue OryHydraService::Error => e
      redirect_to root_path, alert: "Error communicating with Hydra: #{e.message}"
    rescue => e
      redirect_to root_path, alert: "Error rejecting login request: #{e.message}"
    end
  end
end
