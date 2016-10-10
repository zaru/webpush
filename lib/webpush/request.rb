require 'jwt'
require 'base64'

module Webpush
  include Urlsafe

  class ResponseError < RuntimeError
  end

  class InvalidSubscription < ResponseError
  end

  # It is temporary URL until supported by the GCM server.
  GCM_URL = 'https://android.googleapis.com/gcm/send'
  TEMP_GCM_URL = 'https://gcm-http.googleapis.com/gcm'

  class Request
    include Urlsafe

    def initialize(message: "", subscription:, vapid:, **options)
      endpoint = subscription.fetch(:endpoint)
      @endpoint = endpoint.gsub(GCM_URL, TEMP_GCM_URL)
      @vapid = vapid

      @payload = build_payload(message, subscription)

      @options = default_options.merge(options)
    end

    def perform
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
        headers["Content-Encoding"] = "aesgcm128"
        headers["Encryption"] = "salt=#{salt_param}"
        headers["Crypto-Key"] = "dh=#{dh_param}"
      end

      if api_key?
        headers["Authorization"] = api_key
      else
        vapid_headers = build_vapid_headers
        headers["Authorization"] = vapid_headers["Authorization"]
        headers["Crypto-Key"] = [ headers["Crypto-Key"], vapid_headers["Crypto-Key"] ].compact.join(";")
      end

      headers
    end

    def build_vapid_headers
      audience = uri.scheme + "://" + uri.host
      Vapid.headers(@vapid.merge(audience: audience))
    end

    def body
      @payload.fetch(:ciphertext, "")
    end

    private

    def uri
      @uri ||= URI.parse(@endpoint)
    end

    def ttl
      @options.fetch(:ttl).to_s
    end

    def dh_param
      urlsafe_encode64(@payload.fetch(:server_public_key))
    end

    def salt_param
      urlsafe_encode64(@payload.fetch(:salt))
    end

    def default_options
      {
        ttl: 60*60*24*7*4 # 4 weeks
      }
    end

    def build_payload(message, subscription)
      return {} if message.nil? || message.empty?

      encrypt_payload(message, subscription.fetch(:keys))
    end

    def encrypt_payload(message, p256dh:, auth:)
      Webpush::Encryption.encrypt(message, p256dh, auth)
    end

    def api_key
      @options.fetch(:api_key, nil)
    end

    def api_key?
      !(api_key.nil? || api_key.empty?) && @endpoint =~ /\Ahttps:\/\/(android|gcm-http)\.googleapis\.com/
    end
  end
end
