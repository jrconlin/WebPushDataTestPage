var port;

self.addEventListener('push', function(event)  {
    /* Push events arrive when a push message is received.
       They should include a .data component that is the decrypted
       content of the message.
    */
    console.info("**** Recv'd a push message::", JSON.stringify(event));

    if (event.data) {
        // Data is a accessor. Data may be in one of several formats.
        // See: https://w3c.github.io/push-api/#pushmessagedata-interface
        // You can use the following methods to fetch out the info:
        // event.data.text() => as a UTF-8 text string
        // event.data.arrayBuffer() => as a binary buffer
        // event.data.blob() => Rich content format
        // event.data.json() => JSON content
        //
        // Since we sent this in as text, read it out as text.
        let content = event.data.text();
        console.log("** swPush:", content);
        for(let k in self) {
            console.log("self.", k);
        }
        for(let k in this) {
            console.log("this.", k);
        }
        // TODO: send the event to the parent page
        self.postMessage(content);
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
