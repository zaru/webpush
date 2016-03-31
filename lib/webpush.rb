require 'webpush/version'
require 'openssl'
require 'base64'
require 'hkdf'
require 'net/http'
require 'json'

module Webpush

  # It is temporary URL until supported by the GCM server.
  GCM_URL = 'https://android.googleapis.com/gcm/send'
  TEMP_GCM_URL = 'https://gcm-http.googleapis.com/gcm'

  class << self
    def payload_send(message:, endpoint:, p256dh:, auth:, api_key:)
      endpoint = endpoint.gsub(GCM_URL, TEMP_GCM_URL)
      p256dh = unescape_base64(p256dh)
      auth = unescape_base64(auth)

      payload = encrypt(message, p256dh, auth)
      gcm_post(endpoint, payload, api_key)
    end

    private

    def gcm_post(endpoint, payload, api_key)
      begin
        uri = URI.parse(endpoint)
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = true
        http.verify_mode = OpenSSL::SSL::VERIFY_NONE
        header = {
          "Encryption" => "salt=#{Base64.urlsafe_encode64(payload[:salt]).delete('=')}",
          "Crypto-Key" => "dh=#{Base64.urlsafe_encode64(payload[:server_public_key_bn]).delete('=')}",
          "Authorization" => "key=#{api_key}"
        }
        req = Net::HTTP::Post.new(uri.request_uri, header)
        req.body = payload[:ciphertext]
        res = http.request(req)
        return ("201" == res.code) ? true : false
      rescue
        return false
      end
    end

    def encrypt(message, p256dh, auth)
      group_name = "prime256v1"
      salt = Random.new.bytes(16)

      server = OpenSSL::PKey::EC.new(group_name)
      server.generate_key
      server_public_key_bn = server.public_key.to_bn

      group = OpenSSL::PKey::EC::Group.new(group_name)
      client_public_key_hex = Base64.decode64(p256dh).unpack("H*").first
      client_public_key_bn = OpenSSL::BN.new(client_public_key_hex, 16)
      client_public_key = OpenSSL::PKey::EC::Point.new(group, client_public_key_bn)

      shared_secret = server.dh_compute_key(client_public_key)

      clientAuthToken = Base64.decode64(auth)

      prk = HKDF.new(shared_secret, :salt => clientAuthToken, :algorithm => 'SHA256', :info => "Content-Encoding: auth\0").next_bytes(32)

      context = create_context(client_public_key_bn, server_public_key_bn)

      content_encryption_key_info = create_info('aesgcm', context)
      content_encryption_key = HKDF.new(prk, :salt => salt, :info => content_encryption_key_info).next_bytes(16)

      nonce_info = create_info('nonce', context)
      nonce = HKDF.new(prk, :salt => salt, :info => nonce_info).next_bytes(12)

      ciphertext = encrypt_payload(message, content_encryption_key, nonce)

      {
        ciphertext: ciphertext,
        salt: salt,
        server_public_key_bn: convert16bit(server_public_key_bn)
      }
    end

    def create_context(clientPublicKey, serverPublicKey)
      c = convert16bit(clientPublicKey)
      s = convert16bit(serverPublicKey)
      context = "\0"
      context += [c.bytesize].pack("n*")
      context += c
      context += [s.bytesize].pack("n*")
      context += s
      context
    end

    def encrypt_payload(plaintext, content_encryption_key, nonce)
      cipher = OpenSSL::Cipher.new('aes-128-gcm')
      cipher.encrypt
      cipher.key = content_encryption_key
      cipher.iv = nonce
      padding = cipher.update("\0\0")
      text = cipher.update(plaintext)

      e_text = padding + text + cipher.final
      e_tag = cipher.auth_tag

      e_text + e_tag
    end

    def create_info(type, context)
      info = "Content-Encoding: "
      info += type
      info += "\0"
      info += "P-256"
      info += context
      info
    end

    def convert16bit(key)
      [key.to_s(16)].pack("H*")
    end

    def unescape_base64(base64)
      base64.gsub(/_|\-/, "_" => "/", "-" => "+")
    end
  end

end
