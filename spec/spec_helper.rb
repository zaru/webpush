$LOAD_PATH.unshift File.expand_path('../../lib', __FILE__)
require 'pry'
require 'webpush'
require 'webmock/rspec'
WebMock.disable_net_connect!(allow_localhost: true)

def vapid_options
  {
    audience: "http://example.com",
    subject: "mailto:recipient@example.com",
    public_key: "BB9KQDaypj3mJCyrFbF5EDm-UrfnIGeomy0kYL56Mddi3LG6AFEMB_DnWUXSAmNFNOaIgTlXrT3dk2krmp9SPyg=",
    private_key: "JYQ5wbkNfJ2b1Kv_t58cUJJENBIIboVv5Ijzk6a5yH8="
  }
end
