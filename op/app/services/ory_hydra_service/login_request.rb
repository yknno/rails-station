class OryHydraService
  class LoginRequest
    attr_reader :raw

    def initialize(raw)
      @raw = raw || {}
    end

    def skip?
      raw["skip"] == true
    end

    def subject
      raw["subject"]
    end

    def request_url
      raw["request_url"]
    end

    def prompt_login?
      return false if request_url.blank?

      begin
        uri = URI.parse(request_url)
        params_hash = Rack::Utils.parse_query(uri.query || "")
        prompt_param = params_hash["prompt"]
        prompt_param.to_s.split(/\s+/).include?("login")
      rescue => e
        Rails.logger.error "Failed to parse prompt parameter from request_url: #{e.message}"
        false
      end
    end
  end
end
