require 'spec_helper'

describe Webpush do
  it 'has a version number' do
    expect(Webpush::VERSION).not_to be nil
  end

  shared_examples 'request headers' do
    let(:message) { JSON.generate({ body: 'body' }) }
    let(:p256dh) { 'BN4GvZtEZiZuqFxSKVZfSfluwKBD7UxHNBmWkfiZfCtgDE8Bwh-_MtLXbBxTBAWH9r7IPKL0lhdcaqtL1dfxU5E=' }
    let(:auth) { 'Q2BoAjC09xH3ywDLNJr-dA==' }
    let(:ciphertext) { "+\xB8\xDBT}\x13\xB6\xDD.\xF9\xB0\xA7\xC8\xD2\x80\xFD\x99#\xF7\xAC\x83\xA4\xDB,\x1F\xB5\xB9w\x85>\xF7\xADr" }
    let(:salt) { "X\x97\x953\xE4X\xF8_w\xE7T\x95\xC51q\xFE" }
    let(:server_public_key_bn) { "\x04\b-RK9w\xDD$\x16lFz\xF9=\xB4~\xC6\x12k\xF3\xF40t\xA9\xC1\fR\xC3\x81\x80\xAC\f\x7F\xE4\xCC\x8E\xC2\x88 n\x8BB\xF1\x9C\x14\a\xFA\x8D\xC9\x80\xA1\xDDyU\\&c\x01\x88#\x118Ua" }
    let(:shared_secret) { "\t\xA7&\x85\t\xC5m\b\xA8\xA7\xF8B{1\xADk\xE1y'm\xEDE\xEC\xDD\xEDj\xB3$s\xA9\xDA\xF0" }
    let(:payload) { { ciphertext: ciphertext, salt: salt, server_public_key_bn: server_public_key_bn, shared_secret: shared_secret } }
    let(:expected_body) { "+\xB8\xDBT}\x13\xB6\xDD.\xF9\xB0\xA7\xC8\xD2\x80\xFD\x99#\xF7\xAC\x83\xA4\xDB,\x1F\xB5\xB9w\x85>\xF7\xADr" }
    let(:expected_headers) do
      {
        'Accept'=>'*/*',
        'Accept-Encoding'=>'gzip;q=1.0,deflate;q=0.6,identity;q=0.3',
        'Content-Encoding'=>'aesgcm',
        'Content-Type'=>'application/octet-stream',
        'Crypto-Key'=>'dh=BAgtUks5d90kFmxGevk9tH7GEmvz9DB0qcEMUsOBgKwMf-TMjsKIIG6LQvGcFAf6jcmAod15VVwmYwGIIxE4VWE',
        'Encryption'=>'salt=WJeVM-RY-F9351SVxTFx_g',
        'Ttl'=>'2419200',
        'User-Agent'=>'Ruby'
      }
    end

    before do
      allow(Webpush::Encryption).to receive(:encrypt).and_return(payload)
    end

    it 'calls the relevant service with the correct headers' do
      expect(Webpush::Encryption).to receive(:encrypt).and_return(payload)

      stub_request(:post, expected_endpoint).
        with(body: expected_body, headers: expected_headers).
        to_return(status: 201, body: "", headers: {})

      result = Webpush.payload_send(message: message, endpoint: endpoint, p256dh: p256dh, auth: auth)

      expect(result).to be(true)
    end

    it 'returns false for unsuccessful status code by default' do
      stub_request(:post, expected_endpoint).
        to_return(status: 401, body: "", headers: {})

      result = Webpush.payload_send(message: message, endpoint: endpoint, p256dh: p256dh, auth: auth)

      expect(result).to be(false)
    end

    it 'returns false on error by default' do
      stub_request(:post, expected_endpoint).to_raise(StandardError)

      result = Webpush.payload_send(message: message, endpoint: endpoint, p256dh: p256dh, auth: auth)

      expect(result).to be(false)
    end

    it 'inserts Authorization header when present' do
      api_key = SecureRandom.hex(16)
      expected_headers.merge!('Authorization' => "key=#{api_key}")

      stub_request(:post, expected_endpoint).
        with(body: expected_body, headers: expected_headers).
        to_return(status: 201, body: "", headers: {})

      Webpush.payload_send(message: message, endpoint: endpoint, p256dh: p256dh, auth: auth, api_key: api_key)
    end

    it 'does not insert Authorization header when blank' do
      stub_request(:post, expected_endpoint).
        with(body: expected_body, headers: expected_headers).
        to_return(status: 201, body: "", headers: {})

      Webpush.payload_send(message: message, endpoint: endpoint, p256dh: p256dh, auth: auth, api_key: "")
      Webpush.payload_send(message: message, endpoint: endpoint, p256dh: p256dh, auth: auth, api_key: nil)
    end

    it 'message and encryption keys are optional' do
      expect(Webpush::Encryption).to_not receive(:encrypt)

      expected_headers.delete('Crypto-Key')
      expected_headers.delete('Content-Encoding')
      expected_headers.delete('Encryption')

      stub_request(:post, expected_endpoint).
        with(body: nil, headers: expected_headers).
        to_return(status: 201, body: "", headers: {})

      Webpush.payload_send(endpoint: endpoint)
    end
  end

  context 'chrome endpoint' do
    let(:endpoint) { 'https://android.googleapis.com/gcm/send/subscription-id' }
    let(:expected_endpoint) { 'https://gcm-http.googleapis.com/gcm/subscription-id' }

    include_examples 'request headers'
  end

  context 'firefox endpoint' do
    let(:endpoint) { 'https://updates.push.services.mozilla.com/push/v1/subscription-id' }
    let(:expected_endpoint) { endpoint }

    include_examples 'request headers'
  end
end
