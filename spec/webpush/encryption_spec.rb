require 'spec_helper'
require 'ece'

describe Webpush::Encryption do
  describe '#encrypt' do
    let(:curve) do
      group = 'prime256v1'
      OpenSSL::PKey::EC.new(group)
    end

    let(:p256dh) do
      curve.generate_key
      ecdh_key = curve.public_key.to_bn.to_s(2)
      encode64(ecdh_key)
    end

    let(:auth) { encode64(Random.new.bytes(16)) }

    it 'returns ECDH encrypted cipher text, salt, and server_public_key' do
      payload = Webpush::Encryption.encrypt('Hello World', p256dh, auth)
      salt = payload.byteslice(0, 16)
      rs = payload.byteslice(16, 4).unpack("N*").first
      idlen = payload.byteslice(20).unpack("C*").first
      serverkey16bn = payload.byteslice(21, idlen)
      ciphertext = payload.byteslice(21 + idlen + 1, rs)

      expect(payload.bytesize).to eq(21 + idlen + rs)

      group_name = 'prime256v1'
      group = OpenSSL::PKey::EC::Group.new(group_name)
      server_public_key_bn = OpenSSL::BN.new(serverkey16bn.unpack('H*').first, 16)
      server_public_key = OpenSSL::PKey::EC::Point.new(group, server_public_key_bn)
      shared_secret = curve.dh_compute_key(server_public_key)

      decrypted_data = ECE.decrypt(ciphertext,
                                   key: shared_secret,
                                   salt: salt,
                                   server_public_key: server_public_key_bn,
                                   user_public_key: decode64(p256dh),
                                   auth: decode64(auth))

      expect(decrypted_data).to eq('Hello World')
    end

    it 'returns error when message is blank' do
      expect { Webpush::Encryption.encrypt(nil, p256dh, auth) }.to raise_error(ArgumentError)
      expect { Webpush::Encryption.encrypt('', p256dh, auth) }.to raise_error(ArgumentError)
    end

    it 'returns error when p256dh is blank' do
      expect { Webpush::Encryption.encrypt('Hello world', nil, auth) }.to raise_error(ArgumentError)
      expect { Webpush::Encryption.encrypt('Hello world', '', auth) }.to raise_error(ArgumentError)
    end

    it 'returns error when auth is blank' do
      expect { Webpush::Encryption.encrypt('Hello world', p256dh, '') }.to raise_error(ArgumentError)
      expect { Webpush::Encryption.encrypt('Hello world', p256dh, nil) }.to raise_error(ArgumentError)
    end

    # Bug fix for https://github.com/zaru/webpush/issues/22
    it 'handles unpadded base64 encoded subscription keys' do
      unpadded_p256dh = 'BK74n-ZA6kfMDEuCFbQH1Y5T33p39PvnzNeuD5LqTs8cF-uaQFUHn_v5kwV6dYIIL4nFabxghQNF_vlnAXX7OiU'
      unpadded_auth = '1C1PBkJQsVwD9tkuLR1x5A'

      payload = Webpush::Encryption.encrypt('Hello World', unpadded_p256dh, unpadded_auth)
      encrypted = payload.fetch(:ciphertext)

      decrypted_data = ECE.decrypt(encrypted,
                                   key: payload.fetch(:shared_secret),
                                   salt: payload.fetch(:salt),
                                   server_public_key: payload.fetch(:server_public_key_bn),
                                   user_public_key: decode64(pad64(unpadded_p256dh)),
                                   auth: decode64(pad64(unpadded_auth)))

      expect(decrypted_data).to eq('Hello World')
    end

    def generate_ecdh_key
      group = 'prime256v1'
      curve = OpenSSL::PKey::EC.new(group)
      curve.generate_key
      curve.public_key.to_bn.to_s(2)
    end

    def encode64(bytes)
      Base64.urlsafe_encode64(bytes)
    end

    def decode64(str)
      Base64.urlsafe_decode64(str)
    end

    def pad64(str)
      str = str.ljust((str.length + 3) & ~3, '=') if !str.end_with?('=') && str.length % 4 != 0
      str
    end
  end
end
