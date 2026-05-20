class OryHydraService
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
    response = @conn.get("/admin/oauth2/auth/requests/login") do |req|
      req.params['login_challenge'] = challenge
    end
    raise "Failed to get login request: #{response.status} #{response.body}" unless response.success?
    response.body
  end

  def accept_login_request(challenge, subject)
    payload = {
      subject: subject,
      remember: true,
      remember_for: 3600
    }
    response = @conn.put("/admin/oauth2/auth/requests/login/accept") do |req|
      req.params['login_challenge'] = challenge
      req.body = payload
    end
    raise "Failed to accept login request: #{response.status} #{response.body}" unless response.success?
    response.body
  end

  def reject_login_request(challenge, reason)
    payload = {
      error: "login_rejected",
      error_description: reason
    }
    response = @conn.put("/admin/oauth2/auth/requests/login/reject") do |req|
      req.params['login_challenge'] = challenge
      req.body = payload
    end
    raise "Failed to reject login request: #{response.status} #{response.body}" unless response.success?
    response.body
  end

  # Consent requests
  def get_consent_request(challenge)
    response = @conn.get("/admin/oauth2/auth/requests/consent") do |req|
      req.params['consent_challenge'] = challenge
    end
    raise "Failed to get consent request: #{response.status} #{response.body}" unless response.success?
    response.body
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
    response = @conn.put("/admin/oauth2/auth/requests/consent/accept") do |req|
      req.params['consent_challenge'] = challenge
      req.body = payload
    end
    raise "Failed to accept consent request: #{response.status} #{response.body}" unless response.success?
    response.body
  end

  def reject_consent_request(challenge, reason)
    payload = {
      error: "consent_rejected",
      error_description: reason
    }
    response = @conn.put("/admin/oauth2/auth/requests/consent/reject") do |req|
      req.params['consent_challenge'] = challenge
      req.body = payload
    end
    raise "Failed to reject consent request: #{response.status} #{response.body}" unless response.success?
    response.body
  end

  # Logout requests
  def get_logout_request(challenge)
    response = @conn.get("/admin/oauth2/auth/requests/logout") do |req|
      req.params['logout_challenge'] = challenge
    end
    raise "Failed to get logout request: #{response.status} #{response.body}" unless response.success?
    response.body
  end

  def accept_logout_request(challenge)
    response = @conn.put("/admin/oauth2/auth/requests/logout/accept") do |req|
      req.params['logout_challenge'] = challenge
      req.body = {}
    end
    raise "Failed to accept logout request: #{response.status} #{response.body}" unless response.success?
    response.body
  end
end
