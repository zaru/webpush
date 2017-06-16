require 'spec_helper'

describe Webpush do
  it 'has a version number' do
    expect(Webpush::VERSION).not_to be nil
  end

  shared_examples 'web push protocol standard error handling' do
    it 'raises InvalidSubscription if and only if the combination of status code and message indicate an invalid subscription' do
      stub_request(:post, expected_endpoint).
          to_return(status: 410, body: "", headers: {})
      expect { subject }.to raise_error(Webpush::InvalidSubscription)

      stub_request(:post, expected_endpoint).
          to_return(status: [400, "UnauthorizedRegistration"], body: "", headers: {})
      expect { subject }.to raise_error(Webpush::InvalidSubscription)

      stub_request(:post, expected_endpoint).
          to_return(status: 400, body: "", headers: {})
      expect { subject }.not_to raise_error(Webpush::InvalidSubscription)
    end

    it 'raises ExpiredSubscription if the API returns a 404 Error' do
      stub_request(:post, expected_endpoint).
          to_return(status: 404, body: "", headers: {})
      expect { subject }.to raise_error(Webpush::ExpiredSubscription)
    end

    it 'raises PayloadTooLarge if the API returns a 413 Error' do
      stub_request(:post, expected_endpoint).
          to_return(status: 413, body: "", headers: {})
      expect { subject }.to raise_error(Webpush::PayloadTooLarge)
    end

    it 'raises TooManyRequests if the API returns a 429 Error' do
      stub_request(:post, expected_endpoint).
          to_return(status: 429, body: "", headers: {})
      expect { subject }.to raise_error(Webpush::TooManyRequests)
    end

    it 'raises ResponseError for unsuccessful status code by default' do
      stub_request(:post, expected_endpoint).
        to_return(status: 401, body: "", headers: {})

      expect { subject }.to raise_error(Webpush::ResponseError)
    end

    it 'supplies the original status code on the ResponseError' do
      stub_request(:post, expected_endpoint).
        to_return(status: 401, body: "Oh snap", headers: {})

      expect { subject }.to raise_error { |error|
        expect(error).to be_a(Webpush::ResponseError)
        expect(error.response.code).to eq '401'
        expect(error.response.body).to eq 'Oh snap'
      }
    end

    it 'sets the error message to be the host + stringified response' do
      stub_request(:post, expected_endpoint).
        to_return(status: 401, body: "Oh snap", headers: {})

      host = URI.parse(expected_endpoint).host

      expect { subject }.to raise_error { |error|
        expect(error.message).to eq(
          "host: #{host}, #<Net::HTTPUnauthorized 401  readbody=true>\nbody:\nOh snap"
        )
      }
    end

    it 'raises exception on error by default' do
      stub_request(:post, expected_endpoint).to_raise(StandardError)

      expect { subject }.to raise_error
    end
  end

  shared_examples 'request headers with VAPID' do
    let(:message) { JSON.generate({ body: 'body' }) }
    let(:p256dh) { 'BN4GvZtEZiZuqFxSKVZfSfluwKBD7UxHNBmWkfiZfCtgDE8Bwh-_MtLXbBxTBAWH9r7IPKL0lhdcaqtL1dfxU5E=' }
    let(:auth) { 'Q2BoAjC09xH3ywDLNJr-dA==' }
    let(:ciphertext) { "+\xB8\xDBT}\x13\xB6\xDD.\xF9\xB0\xA7\xC8\xD2\x80\xFD\x99#\xF7\xAC\x83\xA4\xDB,\x1F\xB5\xB9w\x85>\xF7\xADr" }
    let(:salt) { "X\x97\x953\xE4X\xF8_w\xE7T\x95\xC51q\xFE" }
    let(:server_public_key) { "\x04\b-RK9w\xDD$\x16lFz\xF9=\xB4~\xC6\x12k\xF3\xF40t\xA9\xC1\fR\xC3\x81\x80\xAC\f\x7F\xE4\xCC\x8E\xC2\x88 n\x8BB\xF1\x9C\x14\a\xFA\x8D\xC9\x80\xA1\xDDyU\\&c\x01\x88#\x118Ua" }
    let(:shared_secret) { "\t\xA7&\x85\t\xC5m\b\xA8\xA7\xF8B{1\xADk\xE1y'm\xEDE\xEC\xDD\xEDj\xB3$s\xA9\xDA\xF0" }
    let(:payload) { { ciphertext: ciphertext, salt: salt, server_public_key: server_public_key, shared_secret: shared_secret } }
    let(:expected_body) { "+\xB8\xDBT}\u0013\xB6\xDD.\xF9\xB0\xA7\xC8Ҁ\xFD\x99#\xF7\xAC\x83\xA4\xDB,\u001F\xB5\xB9w\x85>\xF7\xADr" }
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

    let(:vapid_headers) do
      {
        'Authorization' => 'WebPush jwt.encoded.payload',
        'Crypto-Key' => 'p256ecdsa=' + vapid_public_key.delete('=')
      }
    end

    before do
      allow(Webpush::Encryption).to receive(:encrypt).and_return(payload)
      allow(JWT).to receive(:encode).and_return('jwt.encoded.payload')
    end

    subject { Webpush.payload_send(
      message: message,
      endpoint: endpoint,
      p256dh: p256dh,
      auth: auth,
      vapid: vapid_options)
    }

    it 'calls the relevant service with the correct headers' do
      expect(Webpush::Encryption).to receive(:encrypt).and_return(payload)

      expected_headers['Crypto-Key'] += ";" + vapid_headers['Crypto-Key']
      expected_headers['Authorization'] = vapid_headers['Authorization']

      stub_request(:post, expected_endpoint).
        with(body: expected_body, headers: expected_headers).
        to_return(status: 201, body: "", headers: {})

      result = subject

      expect(result).to be_a(Net::HTTPCreated)
      expect(result.code).to eql('201')
    end

    include_examples 'web push protocol standard error handling'

    it 'message is optional' do
      expect(Webpush::Encryption).to_not receive(:encrypt)

      expected_headers.delete('Crypto-Key')
      expected_headers.delete('Content-Encoding')
      expected_headers.delete('Encryption')

      stub_request(:post, expected_endpoint).
        with(body: nil, headers: expected_headers).
        to_return(status: 201, body: "", headers: {})

      Webpush.payload_send(endpoint: endpoint)
    end

    it 'vapid options are optional' do
      expect(Webpush::Encryption).to receive(:encrypt).and_return(payload)

      expected_headers.delete('Crypto-Key')
      expected_headers.delete('Authorization')

      stub_request(:post, expected_endpoint).
        with(body: expected_body, headers: expected_headers).
        to_return(status: 201, body: "", headers: {})

      result = Webpush.payload_send(
        message: message,
        endpoint: endpoint,
        p256dh: p256dh,
        auth: auth)

      expect(result).to be_a(Net::HTTPCreated)
      expect(result.code).to eql('201')
    end
  end

  context 'chrome FCM endpoint' do
    let(:endpoint) { 'https://fcm.googleapis.com/gcm/send/subscription-id' }
    let(:expected_endpoint) { endpoint }

    include_examples 'request headers with VAPID'
  end

  context 'firefox endpoint' do
    let(:endpoint) { 'https://updates.push.services.mozilla.com/push/v1/subscription-id' }
    let(:expected_endpoint) { endpoint }

    include_examples 'request headers with VAPID'
  end

  context 'chrome GCM endpoint: request headers with GCM api key' do
    let(:endpoint) { 'https://android.googleapis.com/gcm/send/subscription-id' }
    let(:expected_endpoint) { 'https://gcm-http.googleapis.com/gcm/subscription-id' }

    let(:message) { JSON.generate({ body: 'body' }) }
    let(:p256dh) { 'BN4GvZtEZiZuqFxSKVZfSfluwKBD7UxHNBmWkfiZfCtgDE8Bwh-_MtLXbBxTBAWH9r7IPKL0lhdcaqtL1dfxU5E=' }
    let(:auth) { 'Q2BoAjC09xH3ywDLNJr-dA==' }
    let(:ciphertext) { "+\xB8\xDBT}\x13\xB6\xDD.\xF9\xB0\xA7\xC8\xD2\x80\xFD\x99#\xF7\xAC\x83\xA4\xDB,\x1F\xB5\xB9w\x85>\xF7\xADr" }
    let(:salt) { "X\x97\x953\xE4X\xF8_w\xE7T\x95\xC51q\xFE" }
    let(:server_public_key) { "\x04\b-RK9w\xDD$\x16lFz\xF9=\xB4~\xC6\x12k\xF3\xF40t\xA9\xC1\fR\xC3\x81\x80\xAC\f\x7F\xE4\xCC\x8E\xC2\x88 n\x8BB\xF1\x9C\x14\a\xFA\x8D\xC9\x80\xA1\xDDyU\\&c\x01\x88#\x118Ua" }
    let(:shared_secret) { "\t\xA7&\x85\t\xC5m\b\xA8\xA7\xF8B{1\xADk\xE1y'm\xEDE\xEC\xDD\xEDj\xB3$s\xA9\xDA\xF0" }
    let(:payload) { { ciphertext: ciphertext, salt: salt, server_public_key: server_public_key, shared_secret: shared_secret } }
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

    let(:subscription) {  }

    before do
      allow(Webpush::Encryption).to receive(:encrypt).and_return(payload)
    end

    subject { Webpush.payload_send(message: message, endpoint: endpoint, p256dh: p256dh, auth: auth, api_key: "GCM_API_KEY") }

    it 'calls the relevant service with the correct headers' do
      expect(Webpush::Encryption).to receive(:encrypt).and_return(payload)

      stub_request(:post, expected_endpoint).
        with(body: expected_body, headers: expected_headers).
        to_return(status: 201, body: "", headers: {})

      result = subject

      expect(result).to be_a(Net::HTTPCreated)
      expect(result.code).to eql('201')
    end

    include_examples 'web push protocol standard error handling'

    it 'message and encryption keys are optional' do
      expect(Webpush::Encryption).to_not receive(:encrypt)

      expected_headers.delete('Crypto-Key')
      expected_headers.delete('Content-Encoding')
      expected_headers.delete('Encryption')

      stub_request(:post, expected_endpoint).
        with(body: nil, headers: expected_headers).
        to_return(status: 201, body: "", headers: {})

      Webpush.payload_send(endpoint: endpoint, api_key: 'GCM_API_KEY')
    end
  end
end
