require "jwt"

class ActiveSession < ApplicationRecord
  def expired?
    expires_at.present? && expires_at < Time.current
  end

  def claims
    return {} if raw_id_token.blank?
    # Decode without signature verification since it was verified during sign-in
    JWT.decode(raw_id_token, nil, false).first rescue {}
  end

  def user_email
    claims["email"]
  end
end
