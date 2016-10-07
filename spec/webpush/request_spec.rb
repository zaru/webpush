require 'spec_helper'

describe Webpush::Request do
  describe '#headers' do
    let(:request) { build_request("endpoint", vapid: vapid_options) }

    it { expect(request.headers['Content-Type']).to eq('application/octet-stream') }
    it { expect(request.headers['Ttl']).to eq('2419200') }

    describe 'from :payload' do
      it 'inserts encryption headers for valid payload' do
        payload = {
          ciphertext: "ciphertext",
          server_public_key: "server_public_key",
          salt: "salt"
        }
        request = build_request("endpoint", payload: payload)

        expect(request.headers['Content-Encoding']).to eq("aesgcm")
        expect(request.headers['Encryption']).to eq("keyid=p256dh;salt=c2FsdA")
        expect(request.headers['Crypto-Key']).to eq("keyid=p256dh;dh=c2VydmVyX3B1YmxpY19rZXk;p256ecdsa="+vapid_options[:public_key].delete('='))
      end
    end

    describe 'from :ttl' do
      it 'can override Ttl with :ttl option with string' do
        request = build_request("endpoint", ttl: '300', vapid: vapid_options)

        expect(request.headers['Ttl']).to eq('300')
      end

      it 'can override Ttl with :ttl option with fixnum' do
        request = build_request("endpoint", ttl: 60 * 5)

        expect(request.headers['Ttl']).to eq('300')
      end
    end
  end

  describe '#body' do
    it 'extracts :ciphertext from the :payload argument' do
      request = build_request('endpoint', payload: { ciphertext: 'encrypted' }, vapid: vapid_options)

      expect(request.body).to eq('encrypted')
    end

    it 'is empty string when no :ciphertext' do
      request = build_request('endpoint', payload: {})

      expect(request.body).to eq('')
    end

    it 'is empty string when no :payload' do
      request = build_request('endpoint')

      expect(request.body).to eq('')
    end
  end

  def build_request(endpoint, options = {})
    Webpush::Request.new(endpoint, {vapid: vapid_options}.merge(options))
  end
end
