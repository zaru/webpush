module Webpush
  class Error < RuntimeError; end

  class ConfigurationError < Error; end

  class ResponseError < Error; end

  class InvalidSubscription < ResponseError; end
end
