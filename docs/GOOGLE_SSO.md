# Copy the Termius desktop SSO callback

Start `termius-mcp-rs login google`, open the printed URL, and complete sign-in.
When asked to launch the Termius desktop app, decline so that you can copy the
callback into the Rust CLI. A callback started in another login session will
not match the stored request ID.

The original source snapshot provides this helper for a redirect page with no
copyable link. On the **Termius account redirect page**, open browser developer
tools and run it. It reads that page's authenticated Firebase state and displays
the callback locally; it does not send the callback elsewhere.

```js
(async () => {
  const requestId = new URLSearchParams(location.search).get('request');
  const db = await new Promise((resolve, reject) => {
    const req = indexedDB.open('firebaseLocalStorageDb');
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
  const rows = await new Promise((resolve, reject) => {
    const req = db.transaction('firebaseLocalStorage')
      .objectStore('firebaseLocalStorage').getAll();
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
  db.close();
  const user = rows.map(row => row.value)
    .find(value => value && value.stsTokenManager);
  if (!user || !requestId) throw new Error('Finish Google sign-in on this page first.');
  const callback = 'termius://app/continue-sso?email=' + encodeURIComponent(user.email)
    + '&firebaseToken=' + encodeURIComponent(user.stsTokenManager.accessToken)
    + '&requestId=' + encodeURIComponent(requestId);
  prompt('Copy this URL into termius-mcp-rs login', callback);
})();
```

The callback contains a bearer credential. Paste it only into the login flow
you started, do not include it in issues, logs or screenshots, and clear the
clipboard afterward. Enter the Termius vault encryption password when prompted.
This helper depends on the original web page's storage layout; real Google SSO
has not been verified in this port's offline test environment.
