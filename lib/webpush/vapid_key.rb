module Webpush
  class VapidKey
    def self.from_keys(public_key, private_key)
      key = new
      key.public_key = public_key
      key.private_key = private_key

      key
    end

    attr_reader :curve

    def initialize
      @curve = OpenSSL::PKey::EC.new('prime256v1')
      @curve.generate_key
    end

    # Retrieve the encoded EC public key for server-side storage
    # @return encoded binary representaion of 65-byte VAPID public key
    def public_key
      encode64(curve.public_key.to_bn.to_s(2))
    end

    # Retrieve EC public key for Web Push
    # @return the encoded VAPID public key suitable for Web Push transport
    def public_key_for_push_header
      trim_encode64(curve.public_key.to_bn.to_s(2))
    end

    # Convenience
    # @return base64 urlsafe-encoded binary representaion of 32-byte VAPID private key
    def private_key
      Webpush.encode64(curve.private_key.to_s(2))
    end

    def public_key=(key)
      @curve.public_key = OpenSSL::PKey::EC::Point.new(group, to_big_num(key))
    end

    def private_key=(key)
      @curve.private_key = to_big_num(key)
    end

    def curve_name
      group.curve_name
    end

    def group
      curve.group
    end

    def to_h
      { public_key: public_key, private_key: private_key }
    end
    alias to_hash to_h

    def inspect
      "#<#{self.class}:#{object_id.to_s(16)} #{to_h.map { |k, v| ":#{k}=#{v}" }.join(" ")}>"
    end

    private

    def to_big_num(key)
      OpenSSL::BN.new(Webpush.decode64(key), 2)
    end

    def encode64(bin)
      Webpush.encode64(bin)
    end

    def trim_encode64(bin)
      encode64(bin).delete('=')
    end
  end
end
