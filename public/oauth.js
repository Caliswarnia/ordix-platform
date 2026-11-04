// Finishes a Google connection from Ordix's own page, so the session cookie is sent (same-site),
// then removes the one-time code from the address bar and returns to the client's workspace.
(function () {
  'use strict';
  var query = location.search;
  history.replaceState(null, '', location.pathname);
  fetch('/oauth/google/finish', { method: 'POST', credentials: 'same-origin',
    headers: { 'content-type': 'application/json', 'x-requested-with': 'ordix' }, body: JSON.stringify({ query: query }) })
    .then(function (r) { return r.json().then(function (d) { return { ok: r.ok, d: d }; }); })
    .then(function (r) {
      if (r.ok) { location.replace('/?connected=google&client=' + encodeURIComponent(r.d.clientId)); return; }
      document.getElementById('title').textContent = 'The connection didn’t finish';
      document.getElementById('msg').textContent = r.d.error || 'Try connecting again.';
      document.getElementById('back').hidden = false;
    })
    .catch(function () {
      document.getElementById('title').textContent = 'The connection didn’t finish';
      document.getElementById('msg').textContent = 'Check your internet connection and try again.';
      document.getElementById('back').hidden = false;
    });
})();
