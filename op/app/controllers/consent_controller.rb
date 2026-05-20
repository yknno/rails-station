class ConsentController < ApplicationController
  # Ensure the user is signed in to give consent
  before_action :authenticate_user!

  def new
    @challenge = params[:consent_challenge]
    if @challenge.blank?
      redirect_to root_path, alert: "Missing consent challenge."
      return
    end

    hydra = OryHydraService.new
    begin
      @consent_request = hydra.get_consent_request(@challenge)
    rescue => e
      redirect_to root_path, alert: "Error communicating with Hydra: #{e.message}"
      return
    end

    # If hydra says we should skip consent screen
    if @consent_request["skip"]
      begin
        accept_response = hydra.accept_consent_request(
          @challenge,
          @consent_request["requested_scope"],
          @consent_request["requested_access_token_audience"],
          current_user
        )
        redirect_to accept_response["redirect_to"], allow_other_host: true
      rescue Faraday::Error => e
        redirect_to root_path, alert: "Error communicating with Hydra: #{e.message}"
      rescue => e
        redirect_to root_path, alert: "Error accepting consent request: #{e.message}"
      end
      return
    end

    @client = @consent_request["client"]
    @requested_scope = @consent_request["requested_scope"]
    @requested_audience = @consent_request["requested_access_token_audience"]
  end

  def create
    challenge = params[:consent_challenge]
    hydra = OryHydraService.new

    if params[:submit] == "accept"
      begin
        # Fetch the originally requested scopes and audience from the request to grant them
        consent_request = hydra.get_consent_request(challenge)
        
        accept_response = hydra.accept_consent_request(
          challenge,
          consent_request["requested_scope"],
          consent_request["requested_access_token_audience"],
          current_user
        )
        redirect_to accept_response["redirect_to"], allow_other_host: true
      rescue Faraday::Error => e
        redirect_to root_path, alert: "Error communicating with Hydra: #{e.message}"
      rescue => e
        redirect_to root_path, alert: "Error accepting consent request: #{e.message}"
      end
    else
      begin
        reject_response = hydra.reject_consent_request(challenge, "User denied consent.")
        redirect_to reject_response["redirect_to"], allow_other_host: true
      rescue => e
        redirect_to root_path, alert: "Error rejecting consent request: #{e.message}"
      end
    end
  end
end
