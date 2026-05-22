module Oidc
  class SessionManager
    class << self
      def handle_callback(auth, oidc_config)
        raw_id_token = auth.credentials&.id_token
        if raw_id_token.blank?
          raise TokenValidationError, "Authentication failed: Missing ID token."
        end

        id_token_claims = JWT.decode(raw_id_token, nil, false).first
        ActiveSession.create_from_id_token!(raw_id_token, id_token_claims)
      rescue JWT::DecodeError => e
        raise TokenValidationError, "Failed to decode verified ID token: #{e.message}"
      end

      def logout_url(active_session, oidc_config)
        raw_id_token = active_session&.raw_id_token
        return nil if raw_id_token.blank?

        uri = URI(oidc_config.logout_endpoint)
        uri.query = URI.encode_www_form(
          id_token_hint: raw_id_token,
          post_logout_redirect_uri: oidc_config.post_logout_redirect_uri
        )
        uri.to_s
      end
    end
  end
end
