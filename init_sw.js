function subscribe() {
    navigator.serviceWorker.register("sw.js").then( function(swReg){
            console.debug("Registering...", swReg);
            swReg.pushManager.subscribe({
                userVisibleOnly:true,
            })
            .then(function(sub) {
                console.info("subscription:", sub);
            })
            .catch(function(err) {
                console.error("ERROR: ", err);
            });
        }
    )
    .catch(function(err) {
        console.error("Registration Error:", err);
    });
}

subscribe();

