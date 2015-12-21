var port;

self.addEventListener('push', function(event) {
    console.log("Recv'd a push message::", event)

    if (event.data) {
        console.log(JSON.stringify(event.data));
    }

  // var messageData = event.data; PushMessageData not yet supported.
});

self.addEventListener('message', function(event) {
    console.log("Handling message event:", event);

});

self.addEventListener('pushsubscriptionchange', function(event) {
    console.log("Push Subscription Change", event);
});

self.addEventListener('registration', function(event){
    console.log("Registration: ", event);
});

self.addEventListener('activate', function(event){
    console.log("Activate : ", event);
    event.waitUntil(self.clients.claim());
    console.log("Activated: ", event);
});


self.addEventListener('install', function(event){
    console.log("Install: ", event)
    event.waitUntil(self.skipWaiting());
    console.log("Installed: ", event);
});

/*
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
*/
