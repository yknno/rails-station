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
    response = @conn.get("/admin/oauth2/auth/requests/login", { login_challenge: challenge })
    raise "Failed to get login request: #{response.status} #{response.body}" unless response.success?
    response.body
  end

  def accept_login_request(challenge, subject)
    payload = {
      subject: subject,
      remember: true,
      remember_for: 3600
    }
    response = @conn.put("/admin/oauth2/auth/requests/login/accept?login_challenge=#{CGI.escape(challenge)}", payload)
    raise "Failed to accept login request: #{response.status} #{response.body}" unless response.success?
    response.body
  end

  def reject_login_request(challenge, reason)
    payload = {
      error: "login_rejected",
      error_description: reason
    }
    response = @conn.put("/admin/oauth2/auth/requests/login/reject?login_challenge=#{CGI.escape(challenge)}", payload)
    raise "Failed to reject login request: #{response.status} #{response.body}" unless response.success?
    response.body
  end

  # Consent requests
  def get_consent_request(challenge)
    response = @conn.get("/admin/oauth2/auth/requests/consent", { consent_challenge: challenge })
    raise "Failed to get consent request: #{response.status} #{response.body}" unless response.success?
    response.body
  end

  def accept_consent_request(challenge, granted_scopes, granted_audience, subject)
    payload = {
      grant_scope: granted_scopes,
      grant_access_token_audience: granted_audience,
      remember: true,
      remember_for: 3600,
      session: {
        id_token: {
          email: subject # Put email in the id_token claims for OIDC
        }
      }
    }
    response = @conn.put("/admin/oauth2/auth/requests/consent/accept?consent_challenge=#{CGI.escape(challenge)}", payload)
    raise "Failed to accept consent request: #{response.status} #{response.body}" unless response.success?
    response.body
  end

  def reject_consent_request(challenge, reason)
    payload = {
      error: "consent_rejected",
      error_description: reason
    }
    response = @conn.put("/admin/oauth2/auth/requests/consent/reject?consent_challenge=#{CGI.escape(challenge)}", payload)
    raise "Failed to reject consent request: #{response.status} #{response.body}" unless response.success?
    response.body
  end

  # Logout requests
  def get_logout_request(challenge)
    response = @conn.get("/admin/oauth2/auth/requests/logout", { logout_challenge: challenge })
    raise "Failed to get logout request: #{response.status} #{response.body}" unless response.success?
    response.body
  end

  def accept_logout_request(challenge)
    response = @conn.put("/admin/oauth2/auth/requests/logout/accept?logout_challenge=#{CGI.escape(challenge)}", {})
    raise "Failed to accept logout request: #{response.status} #{response.body}" unless response.success?
    response.body
  end
end
