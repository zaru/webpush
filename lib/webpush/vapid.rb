module Webpush
  class Vapid
    include Urlsafe

    def self.headers(options)
      new(options).headers
    end

    def initialize(public_key:, private_key:, audience:, subject:, expiration: 24*60*60)
      @public_key = public_key
      @private_key = private_key
      @audience = audience
      @subject = subject
      @expiration = expiration
    end

    def headers
      vapid_key = generate_vapid_key
      jwt = JWT.encode(jwt_payload, vapid_key, 'ES256')
      p256ecdsa = urlsafe_encode64(vapid_key.public_key.to_bn.to_s(2))

      {
        'Authorization' => 'WebPush ' + jwt,
        'Crypto-Key' => 'p256ecdsa=' + p256ecdsa,
      }
    end

    private

    def jwt_payload
      {
        aud: @audience,
        exp: Time.now.to_i + @expiration,
        sub: @subject,
      }
    end

    def generate_vapid_key
      public_key_bn = OpenSSL::BN.new(urlsafe_decode64(@public_key), 2)
      private_key_bn = OpenSSL::BN.new(urlsafe_decode64(@private_key), 2)

      vapid_key = Webpush.generate_key
      vapid_key.public_key = OpenSSL::PKey::EC::Point.new(vapid_key.group, public_key_bn)
      vapid_key.private_key = private_key_bn

      vapid_key
    end
  end

end
