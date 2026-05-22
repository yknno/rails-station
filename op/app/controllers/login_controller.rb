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

    # Check if prompt=login is requested
    request_url = login_request["request_url"]
    prompt_login = false
    if request_url.present?
      begin
        uri = URI.parse(request_url)
        params_hash = Rack::Utils.parse_query(uri.query || "")
        prompt_param = params_hash["prompt"]
        prompt_login = prompt_param.to_s.split(/\s+/).include?("login")
      rescue => e
        Rails.logger.error "Failed to parse prompt parameter from request_url: #{e.message}"
      end
    end

    # Force re-authentication if prompt=login is requested and we haven't triggered sign out
    # for this login challenge yet.
    if prompt_login && session[:prompt_login_triggered_for] != challenge
      session[:prompt_login_triggered_for] = challenge
      sign_out(current_user) if user_signed_in?
      session[:login_challenge] = challenge
      redirect_to new_user_session_path
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
