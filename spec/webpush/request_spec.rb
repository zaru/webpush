require 'spec_helper'

describe Webpush::Request do
  describe '#headers' do
    let(:request) { Webpush::Request.new("endpoint") }

    it { expect(request.headers['Content-Type']).to eq('application/octet-stream') }
    it { expect(request.headers['Ttl']).to eq('2419200') }

    it 'inserts encryption headers for valid payload' do
      payload = {
        ciphertext: "ciphertext",
        server_public_key_bn:
        "server_public_key_bn",
        salt: "salt"
      }
      request = Webpush::Request.new("endpoint", payload: payload)

      expect(request.headers['Content-Encoding']).to eq("aesgcm")
      expect(request.headers['Encryption']).to eq("salt=c2FsdA")
      expect(request.headers['Crypto-Key']).to eq("dh=c2VydmVyX3B1YmxpY19rZXlfYm4")
    end

    it 'inserts Authorization header when api_key present' do
      request = Webpush::Request.new("endpoint", api_key: "api_key")

      expect(request.headers['Authorization']).to eq("key=api_key")
    end

    it 'does not insert Authorization header when api_key blank' do
      request = Webpush::Request.new("endpoint", api_key: nil)

      expect(request.headers['Authorization']).to be_nil

      request = Webpush::Request.new("endpoint", api_key: "")

      expect(request.headers['Authorization']).to be_nil

      request = Webpush::Request.new("endpoint")

      expect(request.headers['Authorization']).to be_nil
    end
  end
end
