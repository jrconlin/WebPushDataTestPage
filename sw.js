/* The service worker is like an extra process or thread that your
 * application can run. It has limited capabilities and permissions.
 * See: https://developer.mozilla.org/en-US/docs/Mozilla/Projects/Social_API/Service_worker_API_reference
 */
'use strict';

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
        console.log("Service worker just got:", content);
        // Send the event to the parent pages.
        event.waitUntil(
          self.clients.matchAll()
           .then(clientList => {
              let sent = false;
              console.debug("Service worker found clients",
                    JSON.stringify(clients));
             clientList.forEach(client => {
                 console.debug("Service worker sending to client...", client);
                 sent = true;
                 client.postMessage({'type':'content','content':content});
             });
             if (sent == false) {
                 throw new Error("No valid client to send to.");
             }
           })
           .catch(err => {
              console.error("Service worker couldn't send message: ", err);
           })
        );
    }
});

/* The following are other events that this service worker could respond to.
 */

self.addEventListener('message', function(event) {
    // A message has been sent to this service worker.
    console.log("sw Handling message event:", event);
});

self.addEventListener('pushsubscriptionchange', function(event) {
    // The Push subscription ID has changed. The App should send this
    // information back to the App Server.
    console.log("sw Push Subscription Change", event);
    event.waitUntil(
        self.clients.matchAll()
           .then(clientList => {
             let sent = false;
             console.debug("Service worker found clients",
                    JSON.stringify(clients));
             clientList.forEach(client => {
                 console.debug("Service worker sending to client...", client);
                 sent = true;
                 client.postMessage({'type':'update'});
             });
             if (sent == false) {
                 throw new Error("No valid client to send to.");
             }
           })
           .catch(err => {
              console.error("Service worker couldn't send message: ", err);
           })
        );

});

self.addEventListener('registration', function(event){
    // The service worker has been registered.
    console.log("sw Registration: ", event);
});


self.addEventListener('install', function(event){
    // The serivce worker has been loaded and installed.
    // The browser aggressively caches the service worker code.
    console.log("sw Install: ", JSON.stringify(event));
    // This replaces currently active service workers with this one
    // making this service worker a singleton.
    event.waitUntil(self.skipWaiting());
    console.log("sw Installed: ", JSON.stringify(event));

});

self.addEventListener('activate', function(event){
    // The service worker is now Active and functioning.
    console.log("sw Activate : ", JSON.stringify(event));
    // Again, ensure that this is the only active service worker for this
    // page.
    event.waitUntil(self.clients.claim());
    console.log("sw Activated: ", JSON.stringify(event));
    navigator.serviceWorker
});
