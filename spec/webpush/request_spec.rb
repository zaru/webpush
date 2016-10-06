require 'spec_helper'

describe Webpush::Request do
  describe '#headers' do
    let(:request) { Webpush::Request.new("endpoint") }

    it { expect(request.headers['Content-Type']).to eq('application/octet-stream') }
    it { expect(request.headers['Ttl']).to eq('2419200') }

    describe 'from :payload' do
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
    end

    describe 'from :ttl' do
      it 'can override Ttl with :ttl option with string' do
        request = Webpush::Request.new("endpoint", ttl: '300')

        expect(request.headers['Ttl']).to eq('300')
      end

      it 'can override Ttl with :ttl option with fixnum' do
        request = Webpush::Request.new("endpoint", ttl: 60 * 5)

        expect(request.headers['Ttl']).to eq('300')
      end
    end
  end

  describe '#body' do
    it 'extracts :ciphertext from the :payload argument' do
      request = Webpush::Request.new('endpoint', payload: { ciphertext: 'encrypted' })

      expect(request.body).to eq('encrypted')
    end

    it 'is empty string when no :ciphertext' do
      request = Webpush::Request.new('endpoint', payload: {})

      expect(request.body).to eq('')
    end

    it 'is empty string when no :payload' do
      request = Webpush::Request.new('endpoint')

      expect(request.body).to eq('')
    end
  end
end
