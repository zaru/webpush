module Webpush
  class Request
    def initialize(endpoint, payload, options)
      @endpoint = endpoint
      @payload = payload

      @options = default_options.merge(options)
    end

    def perform
      uri = URI.parse(@endpoint)
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = true
      http.verify_mode = OpenSSL::SSL::VERIFY_NONE
      req = Net::HTTP::Post.new(uri.request_uri, request_headers)
      req.body = request_body
      res = http.request(req)
      res.code == "201"
    rescue StandardError => e
      false
    end

    private

    def request_body
      @payload.fetch(:ciphertext, "")
    end

    def ttl
      @options[:ttl].to_s
    end

    def api_key
      @options[:api_key]
    end

    def api_key?
      !(api_key.nil? || api_key.empty?)
    end

    def encrypted_payload?
      [:ciphertext, :server_public_key_bn, :salt].all? { |key| @payload.has_key?(key) }
    end

    def request_headers
      headers = {}
      headers["Content-Type"] = "application/octet-stream"
      headers["Ttl"]          = ttl

      if encrypted_payload?
        headers["Content-Encoding"] = "aesgcm"
        headers["Encryption"] = "salt=#{salt_param}"
        headers["Crypto-Key"] = "dh=#{dh_param}"
      end

      headers["Authorization"] = "key=#{api_key}" if api_key?

      headers
    end

    def dh_param
      Base64.urlsafe_encode64(@payload.fetch(:server_public_key_bn)).delete('=')
    end

    def salt_param
      Base64.urlsafe_encode64(@payload.fetch(:salt)).delete('=')
    end

    def default_options
      {
        api_key: nil,
        ttl: 60*60*24*7*4,        # 4 weeks
        raise_exceptions: false
      }
    end
  end
end
