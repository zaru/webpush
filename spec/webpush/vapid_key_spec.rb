require 'spec_helper'

describe Webpush::VapidKey do
  it "generates an elliptic curve" do
    key = Webpush::VapidKey.new
    expect(key.curve).to be_a(OpenSSL::PKey::EC)
    expect(key.curve_name).to eq('prime256v1')
  end

  it "returns an encoded public key" do
    key = Webpush::VapidKey.new

    expect(Base64.urlsafe_decode64(key.public_key).bytesize).to eq(65)
  end

  it "returns an encoded private key" do
    key = Webpush::VapidKey.new

    expect(Base64.urlsafe_decode64(key.private_key).bytesize).to eq(32)
  end

  describe "self.from_keys" do
    it "returns an encoded public key" do
      key = Webpush::VapidKey.from_keys(vapid_public_key, vapid_private_key)

      expect(key.public_key).to eq(vapid_public_key)
    end

    it "returns an encoded private key" do
      key = Webpush::VapidKey.from_keys(vapid_public_key, vapid_private_key)

      expect(key.private_key).to eq(vapid_private_key)
    end
  end
end
