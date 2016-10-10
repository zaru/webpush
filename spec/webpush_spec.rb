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
    let(:server_public_key) { "\x04\b-RK9w\xDD$\x16lFz\xF9=\xB4~\xC6\x12k\xF3\xF40t\xA9\xC1\fR\xC3\x81\x80\xAC\f\x7F\xE4\xCC\x8E\xC2\x88 n\x8BB\xF1\x9C\x14\a\xFA\x8D\xC9\x80\xA1\xDDyU\\&c\x01\x88#\x118Ua" }
    let(:shared_secret) { "\t\xA7&\x85\t\xC5m\b\xA8\xA7\xF8B{1\xADk\xE1y'm\xEDE\xEC\xDD\xEDj\xB3$s\xA9\xDA\xF0" }
    let(:payload) { { ciphertext: ciphertext, salt: salt, server_public_key: server_public_key, shared_secret: shared_secret } }
    let(:expected_body) { "+\xB8\xDBT}\u0013\xB6\xDD.\xF9\xB0\xA7\xC8Ҁ\xFD\x99#\xF7\xAC\x83\xA4\xDB,\u001F\xB5\xB9w\x85>\xF7\xADr" }
    let(:vapid) {{
      public_key: "BB9KQDaypj3mJCyrFbF5EDm-UrfnIGeomy0kYL56Mddi3LG6AFEMB_DnWUXSAmNFNOaIgTlXrT3dk2krmp9SPyg=",
      private_key: "JYQ5wbkNfJ2b1Kv_t58cUJJENBIIboVv5Ijzk6a5yH8=",
      subject: "mailto:example@example.com",
      expiration: 60 * 60
    }}
    let(:expected_headers) do
      {
        'Accept'=>'*/*',
        'Accept-Encoding'=>'gzip;q=1.0,deflate;q=0.6,identity;q=0.3',
        'Content-Encoding'=>'aesgcm128',
        'Content-Type'=>'application/octet-stream',
        'Crypto-Key'=>'dh=BAgtUks5d90kFmxGevk9tH7GEmvz9DB0qcEMUsOBgKwMf-TMjsKIIG6LQvGcFAf6jcmAod15VVwmYwGIIxE4VWE',
        'Encryption'=>'salt=WJeVM-RY-F9351SVxTFx_g',
        'Ttl'=>'2419200',
        'User-Agent'=>'Ruby'
      }
    end

    let(:vapid_headers) do
      {
        'Authorization' => 'Webpush stub.jwt.here',
        'Crypto-Key' => 'p256ecdsa=encoded-public-key'
      }
    end

    before do
      allow(Webpush::Encryption).to receive(:encrypt).and_return(payload)
      allow(Webpush::Vapid).to receive(:headers).and_return(vapid_headers)
    end

    subject { Webpush.payload_send(
      message: message,
      endpoint: endpoint,
      p256dh: p256dh,
      auth: auth,
      vapid: vapid)
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

    it 'raises ResponseError for unsuccessful status code by default' do
      stub_request(:post, expected_endpoint).
        to_return(status: 401, body: "", headers: {})

      expect { subject }.to raise_error(Webpush::ResponseError)
    end

    it 'raises exception on error by default' do
      stub_request(:post, expected_endpoint).to_raise(StandardError)

      expect { subject }.to raise_error
    end
  end

  context 'chrome endpoint' do
    let(:endpoint) { 'https://fcm.googleapis.com/gcm/send/subscription-id' }
    let(:expected_endpoint) { endpoint }

    include_examples 'request headers'
  end

  context 'firefox endpoint' do
    let(:endpoint) { 'https://updates.push.services.mozilla.com/push/v1/subscription-id' }
    let(:expected_endpoint) { endpoint }

    include_examples 'request headers'
  end
end
