class OryHydraService
  class Error < StandardError; end

  def initialize
    @admin_url = ENV.fetch("HYDRA_ADMIN_URL") { "http://localhost:4445" }
    @conn = Faraday.new(url: @admin_url) do |faraday|
      faraday.request :json
      faraday.response :json
      faraday.adapter Faraday.default_adapter
    end
  end

  # Login requests
  def get_login_request(challenge)
    raw = request(:get, "/admin/oauth2/auth/requests/login", params: { login_challenge: challenge })
    LoginRequest.new(raw)
  end

  def accept_login_request(challenge, subject)
    payload = {
      subject: subject,
      remember: true,
      remember_for: 3600
    }
    request(:put, "/admin/oauth2/auth/requests/login/accept", params: { login_challenge: challenge }, body: payload)
  end

  def reject_login_request(challenge, reason)
    payload = {
      error: "login_rejected",
      error_description: reason
    }
    request(:put, "/admin/oauth2/auth/requests/login/reject", params: { login_challenge: challenge }, body: payload)
  end

  # Consent requests
  def get_consent_request(challenge)
    request(:get, "/admin/oauth2/auth/requests/consent", params: { consent_challenge: challenge })
  end

  def accept_consent_request(challenge, granted_scopes, granted_audience, user)
    id_token_claims = {}
    if granted_scopes.include?("email")
      id_token_claims[:email] = user.email
      id_token_claims[:email_verified] = true
    end
    if granted_scopes.include?("profile")
      id_token_claims[:name] = user.email.split('@').first.capitalize
      id_token_claims[:preferred_username] = user.email.split('@').first
    end

    payload = {
      grant_scope: granted_scopes,
      grant_access_token_audience: granted_audience,
      remember: true,
      remember_for: 3600,
      session: {
        id_token: id_token_claims
      }
    }
    request(:put, "/admin/oauth2/auth/requests/consent/accept", params: { consent_challenge: challenge }, body: payload)
  end

  def reject_consent_request(challenge, reason)
    payload = {
      error: "consent_rejected",
      error_description: reason
    }
    request(:put, "/admin/oauth2/auth/requests/consent/reject", params: { consent_challenge: challenge }, body: payload)
  end

  # Logout requests
  def get_logout_request(challenge)
    request(:get, "/admin/oauth2/auth/requests/logout", params: { logout_challenge: challenge })
  end

  def accept_logout_request(challenge)
    request(:put, "/admin/oauth2/auth/requests/logout/accept", params: { logout_challenge: challenge }, body: {})
  end

  private

  def request(method, path, params: {}, body: nil)
    response = @conn.run_request(method, path, body, nil) do |req|
      req.params.update(params) if params.present?
    end

    unless response.success?
      raise Error, "Failed Hydra admin request to #{path}: #{response.status} #{response.body}"
    end

    response.body
  rescue Faraday::Error => e
    raise Error, "Faraday communication error with Hydra: #{e.message}"
  end
end
