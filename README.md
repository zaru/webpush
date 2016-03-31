# WebPushEncryption

This Gem will send the Web Push API. It supports the encryption necessary to payload.

Payload is supported by Chrome50+.

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'web_push_encryption'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install web_push_encryption

## Usage

```
message = {
  hoge: "piyo"
}

WebPushEncryption.send(message: JSON.generate(message),
                       endpoint: "https://android.googleapis.com/gcm/send/eah7hak....",
                       p256dh: "BO/aG9nYXNkZmFkc2ZmZHNmYWRzZmFl...",
                       auth: "aW1hcmthcmFpa3V6ZQ==",
                       api_key: "[GoogleDeveloper APIKEY]")
```

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/[USERNAME]/web_push_encryption.
