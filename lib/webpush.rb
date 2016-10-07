require 'openssl'
require 'base64'
require 'hkdf'
require 'net/http'
require 'json'

require 'webpush/version'
require 'webpush/urlsafe'
require 'webpush/vapid'
require 'webpush/encryption'
require 'webpush/request'

module Webpush

  class << self
    # Deliver the payload to the required endpoint given by the JavaScript
    # PushSubscription. Including an optional message requires p256dh and
    # auth keys from the PushSubscription.
    #
    # @param endpoint [String] the required PushSubscription url
    # @param message [String] the optional payload
    # @param p256dh [String] the user's public ECDH key given by the PushSubscription
    # @param auth [String] the user's private ECDH key given by the PushSubscription
    # @param options [Hash<Symbol,String>] additional options for the notification
    # @option options [#to_s] :ttl Time-to-live in seconds
    def payload_send(endpoint:, message: "", p256dh: "", auth: "", **options)
      payload = build_payload(message, p256dh, auth)

      Webpush::Request.new(endpoint, options.merge(payload: payload)).perform
    end

    # public_key: vapid_key.public_key.to_bn.to_s(2)
    # private_key: vapid_key.private_key.to_s(2)
    def generate_key
      key = OpenSSL::PKey::EC.new('prime256v1')
      key.generate_key
      key
    end

    private

    def build_payload(message, p256dh, auth)
      return {} if message.nil? || message.empty?

      Webpush::Encryption.encrypt(message, p256dh, auth)
    end
  end
end
