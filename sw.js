var port;

self.addEventListener('push', function(event) {
  // var messageData = event.data; PushMessageData not yet supported.

  var title = 'Yay a message.';
  var body = 'Subscription has changed.';
  var icon = 'push-icon.png';
  var tag = 'push';

  event.waitUntil(
    self.registration.showNotification(title, {
      body: body,
      icon: icon,
      tag: tag
    })
  );

  port.postMessage('Subscription has changed.');
});

self.onmessage = function(e) {
  port = e.ports[0];
}
