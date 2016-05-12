require 'spec_helper'

describe Webpush do
  it 'has a version number' do
    expect(Webpush::VERSION).not_to be nil
  end

  shared_examples 'request headers' do
    let(:message) { JSON.generate({ body: 'body' }) }
    let(:p256dh) { 'BJSoGlbnOdsRScNlGmzKirnX9gF7XG1rGgIwP_BkxUcnQ7U_ezqSxyyu_Ghs17nom_orwTYctWfj2ZJsbqNj748' }
    let(:auth) { '2H6Lqvlpul3hdBqDNbCytw' }
    let(:ciphertext) { "\xA5A4e*\xBE\x95\xC7\xE6&\xBA\x05\x15\x00E\x11eQ\xAA!\"\xE7<\xB6\x93\x00}\xE5H\xB4N_\xD8" }
    let(:salt) { "X\x97\x953\xE4X\xF8_w\xE7T\x95\xC51q\xFE" }
    let(:server_public_key_bn) { "\x04\b-RK9w\xDD$\x16lFz\xF9=\xB4~\xC6\x12k\xF3\xF40t\xA9\xC1\fR\xC3\x81\x80\xAC\f\x7F\xE4\xCC\x8E\xC2\x88 n\x8BB\xF1\x9C\x14\a\xFA\x8D\xC9\x80\xA1\xDDyU\\&c\x01\x88#\x118Ua" }
    let(:payload) { { ciphertext: ciphertext, salt: salt, server_public_key_bn: server_public_key_bn } }
    let(:expected_body) { "\xA5A4e*\xBE\x95\xC7\xE6&\xBA\u0005\u0015\u0000E\u0011eQ\xAA!\"\xE7<\xB6\x93\u0000}\xE5H\xB4N_\xD8" }
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
    
    it 'calls the relevant service with the correct headers' do
      expect(Webpush).to receive(:encrypt).and_return(payload)

      stub_request(:post, expected_endpoint).
        with(body: expected_body, headers: expected_headers).
        to_return(:status => 201, :body => "", :headers => {})

      result = Webpush.payload_send(message: message, endpoint: endpoint, p256dh: p256dh, auth: auth)

      expect(result).to be(true)
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
