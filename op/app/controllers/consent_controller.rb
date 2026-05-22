class ConsentController < ApplicationController
  # Ensure the user is signed in to give consent
  before_action :authenticate_user!

  def new
    @challenge = params[:consent_challenge]
    handler = ConsentFlowHandler.new(challenge: @challenge, current_user: current_user)
    result = handler.handle_new

    if result.success?
      if result.action == :redirect_to_hydra
        redirect_to result.redirect_to, allow_other_host: true
      elsif result.action == :render_consent
        @consent_request = result.consent_request
        @client = @consent_request["client"]
        @requested_scope = @consent_request["requested_scope"]
        @requested_audience = @consent_request["requested_access_token_audience"]
      end
    else
      redirect_to root_path, alert: result.error_message
    end
  end

  def create
    challenge = params[:consent_challenge]
    handler = ConsentFlowHandler.new(challenge: challenge, current_user: current_user)

    result = if params[:submit] == "accept"
               handler.handle_accept
             else
               handler.handle_reject
             end

    if result.success?
      redirect_to result.redirect_to, allow_other_host: true
    else
      redirect_to root_path, alert: result.error_message
    end
  end
end
