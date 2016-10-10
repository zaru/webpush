# WebPush

[![Code Climate](https://codeclimate.com/github/zaru/webpush/badges/gpa.svg)](https://codeclimate.com/github/zaru/webpush)
[![Build Status](https://travis-ci.org/zaru/webpush.svg?branch=master)](https://travis-ci.org/zaru/webpush)
[![Gem Version](https://badge.fury.io/rb/webpush.svg)](https://badge.fury.io/rb/webpush)

This gem makes it possible to send push messages to web browsers from Ruby backends using the [Web Push Protocol](https://tools.ietf.org/html/draft-ietf-webpush-protocol-10). It supports the encryption necessary to send messages securely.

Payload is supported by Chrome50+, Firefox48+.

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'webpush'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install webpush

## Usage

Sending a web push message to a visitor of your website requires a number of steps:

1. Your server has generated (one-time) a set of Voluntary Application server Identification (VAPID) keys.
2. To send messages through Chrome, you have registered your site through the Google Developer Console and have obtained a GCM sender id. For using Google's deprecated GCM protocol instead of VAPID, a separate GCM API key from your app settings would also be necessary.
3. In the user's web browser, the user has accepted the prompt to receive notifications from your site.
4. A 'manifest.json' file, linked from your user's page, identifies your app settings, including the GCM sender ID.
5. Also in the user's web browser, a `serviceWorker` is installed and activated and its `pushManager` property is subscribed to push
   events with your VAPID public key, with creates a `subscription` JSON object on the client side.
6. Your server uses `webpush` to send a notification with the `subscription` from the client and an optional payload.

### using the payload

```ruby
message = {
  title: "title",
  body: "body",
  icon: "http://example.com/icon.pn"
}

Webpush.payload_send(
  endpoint: "https://fcm.googleapis.com/gcm/send/eah7hak....",
  message: JSON.generate(message),
  p256dh: "BO/aG9nYXNkZmFkc2ZmZHNmYWRzZmFl...",
  auth: "aW1hcmthcmFpa3V6ZQ==",
  ttl: 600 #optional, ttl in seconds, defaults to 2419200 (4 weeks)
)
```

### not use the payload

```ruby
Webpush.payload_send(
  endpoint: "https://fcm.googleapis.com/gcm/send/eah7hak....",
  ttl: 600 #optional, ttl in seconds, defaults to 2419200 (4 weeks)
)
```

### ServiceWorker sample

see. https://github.com/zaru/web-push-sample

p256dh and auth generate sample code.

```javascript
navigator.serviceWorker.ready.then(function(sw) {
  Notification.requestPermission(function(permission) {
    if(permission !== 'denied') {
      sw.pushManager.subscribe({userVisibleOnly: true}).then(function(s) {
        var data = {
          endpoint: s.endpoint,
          p256dh: btoa(String.fromCharCode.apply(null, new Uint8Array(s.getKey('p256dh')))).replace(/\+/g, '-').replace(/\//g, '_'),
          auth: btoa(String.fromCharCode.apply(null, new Uint8Array(s.getKey('auth')))).replace(/\+/g, '-').replace(/\//g, '_')
        }
        console.log(data);
      });
    }
  });
});
```

payloads received sample code.

```javascript
self.addEventListener("push", function(event) {
  var json = event.data.json();
  self.registration.showNotification(json.title, {
    body: json.body,
    icon: json.icon
  });
});
```

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/zaru/webpush.
