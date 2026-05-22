class LoginFlowHandler
  attr_reader :challenge, :current_user, :session, :hydra

  def initialize(challenge:, current_user:, session:, hydra: OryHydraService.new)
    @challenge = challenge
    @current_user = current_user
    @session = session
    @hydra = hydra
  end

  def handle_new
    if challenge.blank?
      return Result.error("Missing login challenge.")
    end

    begin
      login_request = hydra.get_login_request(challenge)
    rescue => e
      return Result.error("Error communicating with Hydra: #{e.message}")
    end

    # Force re-authentication if prompt=login is requested and we haven't triggered sign out
    # for this login challenge yet.
    if login_request.prompt_login? && session[:prompt_login_triggered_for] != challenge
      session[:prompt_login_triggered_for] = challenge
      session[:login_challenge] = challenge
      return Result.redirect_to_new_session(force_sign_out: true)
    end

    # If hydra says we should skip (session exists in Hydra)
    if login_request.skip?
      begin
        accept_response = hydra.accept_login_request(challenge, login_request.subject)
        return Result.redirect_to_hydra(accept_response["redirect_to"])
      rescue => e
        return Result.error("Error accepting login request: #{e.message}")
      end
    end

    # If user is already signed in on our Rails application
    if current_user.present?
      begin
        accept_response = hydra.accept_login_request(challenge, current_user.id.to_s)
        return Result.redirect_to_hydra(accept_response["redirect_to"])
      rescue OryHydraService::Error => e
        return Result.error("Error communicating with Hydra: #{e.message}")
      rescue => e
        return Result.error("Error accepting login request: #{e.message}")
      end
    end

    # Otherwise, store challenge in session and redirect to Devise sign-in
    session[:login_challenge] = challenge
    Result.redirect_to_new_session(force_sign_out: false)
  end

  def handle_reject
    if challenge.blank?
      return Result.error("Missing login challenge.")
    end

    begin
      reject_response = hydra.reject_login_request(challenge, "User cancelled login.")
      session.delete(:login_challenge)
      Result.redirect_to_hydra(reject_response["redirect_to"])
    rescue OryHydraService::Error => e
      Result.error("Error communicating with Hydra: #{e.message}")
    rescue => e
      Result.error("Error rejecting login request: #{e.message}")
    end
  end

  class Result
    attr_reader :action, :redirect_to, :error_message, :force_sign_out

    def initialize(action:, redirect_to: nil, error_message: nil, force_sign_out: false)
      @action = action
      @redirect_to = redirect_to
      @error_message = error_message
      @force_sign_out = force_sign_out
    end

    def self.redirect_to_hydra(url)
      new(action: :redirect_to_hydra, redirect_to: url)
    end

    def self.redirect_to_new_session(force_sign_out:)
      new(action: :redirect_to_new_session, force_sign_out: force_sign_out)
    end

    def self.error(message)
      new(action: :error, error_message: message)
    end

    def success?
      action != :error
    end
  end
end
