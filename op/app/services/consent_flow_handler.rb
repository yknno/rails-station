class ConsentFlowHandler
  attr_reader :challenge, :current_user, :hydra

  def initialize(challenge:, current_user:, hydra: OryHydraService.new)
    @challenge = challenge
    @current_user = current_user
    @hydra = hydra
  end

  def handle_new
    if challenge.blank?
      return Result.error("Missing consent challenge.")
    end

    begin
      consent_request = hydra.get_consent_request(challenge)
    rescue => e
      return Result.error("Error communicating with Hydra: #{e.message}")
    end

    # If hydra says we should skip consent screen
    if consent_request["skip"]
      begin
        accept_response = hydra.accept_consent_request(
          challenge,
          consent_request["requested_scope"],
          consent_request["requested_access_token_audience"],
          current_user
        )
        return Result.redirect_to_hydra(accept_response["redirect_to"])
      rescue OryHydraService::Error => e
        return Result.error("Error communicating with Hydra: #{e.message}")
      rescue => e
        return Result.error("Error accepting consent request: #{e.message}")
      end
    end

    Result.render_consent(consent_request)
  end

  def handle_accept
    begin
      # Fetch the originally requested scopes and audience from the request to grant them
      consent_request = hydra.get_consent_request(challenge)
      
      accept_response = hydra.accept_consent_request(
        challenge,
        consent_request["requested_scope"],
        consent_request["requested_access_token_audience"],
        current_user
      )
      Result.redirect_to_hydra(accept_response["redirect_to"])
    rescue OryHydraService::Error => e
      Result.error("Error communicating with Hydra: #{e.message}")
    rescue => e
      Result.error("Error accepting consent request: #{e.message}")
    end
  end

  def handle_reject
    begin
      reject_response = hydra.reject_consent_request(challenge, "User denied consent.")
      Result.redirect_to_hydra(reject_response["redirect_to"])
    rescue => e
      Result.error("Error rejecting consent request: #{e.message}")
    end
  end

  class Result
    attr_reader :action, :redirect_to, :error_message, :consent_request

    def initialize(action:, redirect_to: nil, error_message: nil, consent_request: nil)
      @action = action
      @redirect_to = redirect_to
      @error_message = error_message
      @consent_request = consent_request
    end

    def self.redirect_to_hydra(url)
      new(action: :redirect_to_hydra, redirect_to: url)
    end

    def self.render_consent(request)
      new(action: :render_consent, consent_request: request)
    end

    def self.error(message)
      new(action: :error, error_message: message)
    end

    def success?
      action != :error
    end
  end
end
