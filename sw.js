var port;

self.addEventListener('push', function(event) {
    /* Push events arrive when a push message is received.
       They should include a .data component that is the decrypted
       content of the message.
    */
    console.info("**** Recv'd a push message::", JSON.stringify(event));

    if (event.data) {
        console.log("** swPush:", JSON.stringify(event.data));
        // TODO: send the event to the parent page

    }
});

self.addEventListener('message', function(event) {
    console.log("sw Handling message event:", event);
});

self.addEventListener('pushsubscriptionchange', function(event) {
    console.log("sw Push Subscription Change", event);
});

self.addEventListener('registration', function(event){
    console.log("sw Registration: ", event);
});


self.addEventListener('install', function(event){
    console.log("sw Install: ", JSON.stringify(event));
    event.waitUntil(self.skipWaiting());
    console.log("sw Installed: ", JSON.stringify(event));
});

self.addEventListener('activate', function(event){
    console.log("sw Activate : ", JSON.stringify(event));
    event.waitUntil(self.clients.claim());
    console.log("sw Activated: ", JSON.stringify(event));
    navigator.serviceWorker
});

self.onmessage = function(event) {
  console.log("sw Message:", JSON.strigify(event));  
}
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
