require 'openssl'
require 'base64'
require 'hkdf'
require 'net/http'
require 'json'

require 'webpush/version'
require 'webpush/encryption'
require 'webpush/request'

module Webpush

  # It is temporary URL until supported by the GCM server.
  GCM_URL = 'https://android.googleapis.com/gcm/send'
  TEMP_GCM_URL = 'https://gcm-http.googleapis.com/gcm'

  class << self
    def payload_send(message:, endpoint:, p256dh:, auth:, **options)
      endpoint = endpoint.gsub(GCM_URL, TEMP_GCM_URL)

      payload = Webpush::Encryption.encrypt(message, p256dh, auth)

      Webpush::Request.new(endpoint, payload, options).perform
    end
  end
end
