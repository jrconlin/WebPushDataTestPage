# WebPush Crypto Test Page

Much like the [OAuth Test Page](http://jrconlin.github.io/OAuthTestPage/), this page is designed to help library authors and developers a way to understand and audit the various encryption bits needed to send data via [WebPush](https://developer.mozilla.org/en-US/docs/Web/API/Push_API).

Please be advised that sending Data via WebPush is still experimental. Currently this is only supported on Firefox version 45 or later.

[See a live
demo](https://mozilla-services.github.io/WebPushDataTestPage/).

This demo is beta quality. While it works, you may need to refresh several times before things are working correctly. In addition, there's [a known bug](https://bugzilla.mozilla.org/show_bug.cgi?id=1237455) with `fetch()` which prevents the page from sending headers as part of the outbound request. Using the `curl` output should work, however.
