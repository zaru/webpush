require 'jwt'
require 'base64'

module Webpush

  class ResponseError < RuntimeError
  end

  class InvalidSubscription < ResponseError
  end

  class Request
    include Urlsafe

    def initialize(endpoint, vapid:, **options)
      @endpoint = endpoint
      @vapid = vapid

      @options = default_options.merge(options)
      @payload = @options.delete(:payload) || {}
    end

    def perform
      uri = URI.parse(@endpoint)
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = true
      req = Net::HTTP::Post.new(uri.request_uri, headers)
      req.body = body
      resp = http.request(req)

      if resp.is_a?(Net::HTTPGone) ||   #Firefox unsubscribed response
          (resp.is_a?(Net::HTTPBadRequest) && resp.message == "UnauthorizedRegistration")  #Chrome unsubscribed response
        raise InvalidSubscription.new(resp.inspect)
      elsif !resp.is_a?(Net::HTTPSuccess)  #unknown/unhandled response error
        raise ResponseError.new "host: #{uri.host}, #{resp.inspect}\nbody:\n#{resp.body}"
      end

      resp
    end

    def headers
      headers = {}
      headers["Content-Type"] = "application/octet-stream"
      headers["Ttl"]          = ttl

      if @payload.has_key?(:server_public_key)
        headers["Content-Encoding"] = "aesgcm"
        headers["Encryption"] = "keyid=p256dh;salt=#{salt_param}"
        headers["Crypto-Key"] = "keyid=p256dh;dh=#{dh_param}"
      end

      vapid_headers = build_vapid_headers
      headers["Authorization"] = vapid_headers["Authorization"]
      headers["Crypto-Key"] = [
        headers["Crypto-Key"],
        vapid_headers["Crypto-Key"]
      ].compact.join(";")

      headers
    end

    def build_vapid_headers
      Vapid.headers(@vapid)
    end

    def body
      @payload.fetch(:ciphertext, "")
    end

    private

    def ttl
      @options.fetch(:ttl).to_s
    end

    def dh_param
      Base64.urlsafe_encode64(@payload.fetch(:server_public_key)).delete('=')
    end

    def salt_param
      Base64.urlsafe_encode64(@payload.fetch(:salt)).delete('=')
    end

    def default_options
      {
        ttl: 60*60*24*7*4 # 4 weeks
      }
    end
  end
end
