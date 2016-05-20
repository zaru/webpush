module Webpush
  class Request
    def initialize(endpoint, options = {})
      @endpoint = endpoint
      @options = default_options.merge(options)
      @payload = @options.delete(:payload) || {}
    end

    def perform
      uri = URI.parse(@endpoint)
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = true
      http.verify_mode = OpenSSL::SSL::VERIFY_NONE
      req = Net::HTTP::Post.new(uri.request_uri, headers)
      req.body = body
      http.request(req)
    rescue => e
      raise e
    end

    def headers
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

    def body
      @payload.fetch(:ciphertext, "")
    end

    private

    def ttl
      @options.fetch(:ttl).to_s
    end

    def api_key
      @options.fetch(:api_key, nil)
    end

    def api_key?
      !(api_key.nil? || api_key.empty?)
    end

    def encrypted_payload?
      [:ciphertext, :server_public_key_bn, :salt].all? { |key| @payload.has_key?(key) }
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
        ttl: 60*60*24*7*4 # 4 weeks
      }
    end
  end
end
