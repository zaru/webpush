module Webpush
  module Urlsafe
    def urlsafe_encode64(key)
      Base64.urlsafe_encode64(key).delete('=')
    end

    def urlsafe_decode64(key)
      Base64.urlsafe_decode64(key)
    end
  end
end
