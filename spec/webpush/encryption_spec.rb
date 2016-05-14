require 'spec_helper'
require 'ece'

describe Webpush::Encryption do
  describe "#encrypt" do
    let(:p256dh) do
      encode64(generate_ecdh_key)
    end

    let(:auth) { encode64(Random.new.bytes(16)) }

    it "returns ECDH encrypted cipher text, salt, and server_public_key" do
      payload = Webpush::Encryption.encrypt("Hello World", p256dh, auth)

      encrypted = payload.fetch(:ciphertext)

      decrypted_data = ECE.decrypt(encrypted,
        key: payload.fetch(:shared_secret),
        salt: payload.fetch(:salt),
        server_public_key: payload.fetch(:server_public_key_bn),
        user_public_key: decode64(p256dh),
        auth: decode64(auth))

      expect(decrypted_data).to eq("Hello World")
    end

    it 'returns error when message is blank' do
      expect{Webpush::Encryption.encrypt(nil, p256dh, auth)}.to raise_error(ArgumentError)
      expect{Webpush::Encryption.encrypt("", p256dh, auth)}.to raise_error(ArgumentError)
    end

    it 'returns error when p256dh is blank' do
      expect{Webpush::Encryption.encrypt("Hello world", nil, auth)}.to raise_error(ArgumentError)
      expect{Webpush::Encryption.encrypt("Hello world", "", auth)}.to raise_error(ArgumentError)
    end

    it 'returns error when auth is blank' do
      expect{Webpush::Encryption.encrypt("Hello world", p256dh, "")}.to raise_error(ArgumentError)
      expect{Webpush::Encryption.encrypt("Hello world", p256dh, nil)}.to raise_error(ArgumentError)
    end

    def generate_ecdh_key
      group = "prime256v1"
      curve = OpenSSL::PKey::EC.new(group)
      curve.generate_key
      curve.public_key.to_bn.to_s(2)
    end

    def encode64(bytes)
      Base64.urlsafe_encode64(bytes)
    end

    def decode64(bytes)
      Base64.urlsafe_decode64(bytes)
    end
  end
end
