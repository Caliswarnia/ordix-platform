// Ordix browser app: sign-in, workspace choice, and the agency/client screens.
// No inline styles or scripts (the server's Content-Security-Policy forbids them); colors are set through the DOM.
(function () {
  'use strict';
  var root = document.getElementById('root');
  var S = null;           // /api/session
  var clients = [];
  var route = { page: 'overview', client: null, tab: 'seo' };
  var LEVELS = ['none', 'view', 'edit', 'approve'];
  var AREAS = [['seo', 'SEO'], ['site', 'Site health'], ['ads', 'Paid media'], ['social', 'Social'], ['reports', 'Reports'], ['accounts', 'Connected accounts'],
               ['margins', 'Margins'], ['team', 'Team'], ['branding', 'Branding']];
  var CLIENT_AREAS = AREAS.slice(0, 6);
  var AGENCY_ONLY = ['margins', 'team', 'branding'];

  // ---------- helpers ----------
  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); }
  function api(method, path, body) {
    return fetch(path, { method: method, credentials: 'same-origin',
      headers: { 'content-type': 'application/json', 'x-requested-with': 'ordix' }, body: body ? JSON.stringify(body) : undefined })
      .then(function (r) { return r.json().catch(function () { return {}; }).then(function (d) { return { status: r.status, data: d }; }); });
  }
  var toastTimer;
  function toast(msg) { var t = document.getElementById('toast'); t.textContent = msg; t.hidden = false; clearTimeout(toastTimer); toastTimer = setTimeout(function () { t.hidden = true; }, 3000); }
  function can(area, level) { return S && LEVELS.indexOf(S.access[area]) >= LEVELS.indexOf(level); }
  function $(id) { return document.getElementById(id); }
  function setBrand(color) { document.documentElement.style.setProperty('--accent', color || '#0A7A6A'); }
  function when(iso) {
    var d = new Date(iso), now = new Date();
    var t = d.toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' });
    return d.toDateString() === now.toDateString() ? 'Today ' + t : d.toLocaleDateString([], { month: 'short', day: 'numeric' }) + ' ' + t;
  }

  // ---------- sign-in flow ----------
  function card(inner) { root.innerHTML = '<main class="signin"><div class="signin-card">' + inner + '</div></main>'; }

  function showSignIn(msg) {
    document.title = 'Sign in';
    card('<h1>Sign in</h1><form id="f" class="field" novalidate>' +
      '<div class="field"><label for="email">Email</label><input id="email" type="email" autocomplete="username" required></div>' +
      '<div class="field"><label for="pw">Password</label><input id="pw" type="password" autocomplete="current-password" required></div>' +
      '<p class="err" id="err">' + esc(msg || '') + '</p><button class="btn btn-p" type="submit">Continue</button></form>');
    $('email').focus();
    $('f').addEventListener('submit', function (e) {
      e.preventDefault();
      api('POST', '/auth/sign-in', { email: $('email').value, password: $('pw').value }).then(function (r) {
        if (r.status !== 200) { $('err').textContent = r.data.error || 'Sign-in failed'; return; }
        if (r.data.next === 'enroll') showEnroll(r.data); else showCode(r.data.challenge);
      });
    });
  }

  function showEnroll(d) {
    var groups = d.secret.match(/.{1,4}/g).join(' ');
    card('<h1>Set up two-step sign-in</h1><ol class="steps">' +
      '<li>Open an authenticator app on your phone (Google Authenticator, Microsoft Authenticator, 1Password).</li>' +
      '<li>Add an account and enter this key, or <a href="' + esc(d.otpauth) + '">open it in the app</a> on this device.</li></ol>' +
      '<p class="secret" aria-label="Setup key">' + esc(groups) + '</p>' + codeForm('Enter the 6-digit code it shows'));
    wireCode(d.challenge);
  }
  function showCode(challenge) { card('<h1>Enter your code</h1><p class="muted">Open your authenticator app and enter the 6-digit code.</p>' + codeForm('Code')); wireCode(challenge); }
  function codeForm(label) {
    return '<form id="f" novalidate class="field"><div class="field"><label for="code">' + esc(label) + '</label>' +
      '<input id="code" inputmode="numeric" autocomplete="one-time-code" maxlength="7" pattern="[0-9 ]*" required></div>' +
      '<p class="err" id="err"></p><button class="btn btn-p" type="submit">Verify</button></form>';
  }
  function wireCode(challenge) {
    $('code').focus();
    $('f').addEventListener('submit', function (e) {
      e.preventDefault();
      api('POST', '/auth/verify', { challenge: challenge, code: $('code').value }).then(function (r) {
        if (r.status === 200) return afterSignIn(r.data);
        if (/took too long|Sign in again/.test(r.data.error || '')) return showSignIn(r.data.error);
        $('err').textContent = r.data.error || 'That code didn’t work';
      });
    });
  }

  function afterSignIn(me) {
    if (me.mustChangePassword) return showChangePassword();
    if (!me.workspace) return showWorkspaces(me.workspaces);
    loadApp();
  }

  function showChangePassword() {
    card('<h1>Choose your password</h1><p class="muted">Replace your temporary password. Use at least 12 characters.</p>' +
      '<form id="f" novalidate class="field">' +
      '<div class="field"><label for="cur">Temporary password</label><input id="cur" type="password" autocomplete="current-password"></div>' +
      '<div class="field"><label for="nw">New password</label><input id="nw" type="password" autocomplete="new-password" minlength="12"></div>' +
      '<p class="err" id="err"></p><button class="btn btn-p" type="submit">Save password</button></form>');
    $('cur').focus();
    $('f').addEventListener('submit', function (e) {
      e.preventDefault();
      api('POST', '/auth/password', { current: $('cur').value, next: $('nw').value }).then(function (r) {
        if (r.status !== 200) { $('err').textContent = r.data.error; return; }
        api('GET', '/auth/me').then(function (m) { afterSignIn(Object.assign({}, m.data, { mustChangePassword: false })); });
      });
    });
  }

  function showWorkspaces(list) {
    card('<h1>Choose a workspace</h1><p class="muted">You work with more than one agency. You can switch at any time.</p><div class="ws-list">' +
      list.map(function (w) {
        return '<button class="ws-btn" data-ws="' + esc(w.membershipId) + '"><b>' + esc(w.agency) + '</b><span class="muted small">' +
          esc(w.title) + (w.client ? ' · ' + esc(w.client) : '') + '</span></button>';
      }).join('') + '</div>');
    root.querySelectorAll('[data-ws]').forEach(function (b) {
      b.addEventListener('click', function () { chooseWorkspace(b.dataset.ws); });
    });
  }
  function chooseWorkspace(id) {
    api('POST', '/auth/workspace', { membershipId: id }).then(function (r) {
      if (r.status !== 200) return toast(r.data.error || 'That workspace isn’t available');
      route = { page: 'overview', client: null, tab: 'seo' };
      loadApp();
    });
  }

  // ---------- app ----------
  function loadApp() {
    Promise.all([api('GET', '/api/session'), api('GET', '/api/clients')]).then(function (rs) {
      var s = rs[0], c = rs[1];
      if (s.status === 401) return showSignIn();
      if (s.status === 409) return api('GET', '/auth/me').then(function (m) { showWorkspaces(m.data.workspaces); });
      if (s.status === 403) return showChangePassword();
      S = s.data; clients = c.data || [];
      setBrand(S.agency.brandColor);
      document.title = S.agency.name;
      if (S.workspace.clientId) { route.page = 'client'; route.client = S.workspace.clientId; }
      var back = new URLSearchParams(location.search);
      if (back.get('connected') && back.get('client')) {
        route = { page: 'client', client: back.get('client'), tab: 'accounts' };
        history.replaceState(null, '', '/');
        setTimeout(function () { toast('Google connected. Choose the site and property for this client\u2019s dashboards.'); }, 200);
      }
      render();
    });
  }

  function shell(inner) {
    var w = S.workspace, isClient = !!w.clientId;
    var nav = '';
    if (!isClient) {
      nav += '<h4>Agency</h4>' + navBtn('overview', 'Overview') + navBtn('clients', 'Clients');
      nav += '<h4>Clients</h4>' + clients.map(function (c) { return navBtn('client', c.name, c.id); }).join('');
      if (can('team', 'view') || can('branding', 'edit')) nav += '<h4>Admin</h4>';
      if (can('team', 'view')) nav += navBtn('team', 'Team and access');
      if (can('branding', 'edit')) nav += navBtn('branding', 'Branding');
      if (can('team', 'view')) nav += navBtn('activity', 'Activity log');
    } else {
      nav += '<h4>' + esc(w.client) + '</h4>' + navBtn('client', 'Workspace', w.clientId);
    }
    var switcher = S.workspaces.length > 1 ? '<label class="small muted" for="ws">Workspace</label> <select id="ws" class="inline">' +
      S.workspaces.map(function (x) { return '<option value="' + esc(x.membershipId) + '"' + (x.membershipId === w.membershipId ? ' selected' : '') + '>' +
        esc(x.agency) + (x.client ? ' · ' + esc(x.client) : '') + '</option>'; }).join('') + '</select>' : '';
    root.innerHTML = '<header class="topbar"><div class="topbar-in"><div class="brand"><span class="brand-mark">' + esc((S.agency.name || 'A').trim().charAt(0).toUpperCase()) +
      '</span><span>' + esc(S.agency.name) + '</span></div><span class="spacer"></span>' + switcher +
      '<div class="who"><b>' + esc(S.person.fullName) + '</b><br><span class="muted">' + esc(w.title) + '</span></div>' +
      '<button class="btn btn-s" id="signout">Sign out</button></div></header>' +
      '<div class="shell"><nav class="rail" aria-label="Sections">' + nav + '</nav><main class="main" id="main">' + inner + '</main></div>';
    $('signout').addEventListener('click', function () { api('POST', '/auth/sign-out', {}).then(function () { S = null; setBrand(); showSignIn(); }); });
    if ($('ws')) $('ws').addEventListener('change', function () { chooseWorkspace(this.value); });
    root.querySelectorAll('[data-page]').forEach(function (b) {
      b.addEventListener('click', function () { route.page = b.dataset.page; route.client = b.dataset.client || null; route.tab = 'seo'; render(); window.scrollTo(0, 0); });
    });
  }
  function navBtn(page, label, clientId) {
    var cur = route.page === page && (!clientId || route.client === clientId);
    return '<button class="nav" data-page="' + page + '"' + (clientId ? ' data-client="' + esc(clientId) + '"' : '') + (cur ? ' aria-current="page"' : '') + '>' + esc(label) + '</button>';
  }

  function render() {
    var p = route.page;
    if (p === 'overview') return shell(viewOverview());
    if (p === 'clients') { shell(viewClients()); return wireClients(); }
    if (p === 'client') { shell(viewClient()); return wireClient(); }
    if (p === 'team') return loadTeam();
    if (p === 'branding') { shell(viewBranding()); return wireBranding(); }
    if (p === 'activity') return loadActivity();
  }

  // Overview
  function viewOverview() {
    var connected = 0;
    return '<div class="page-head"><div><h1>' + esc(S.agency.name) + '</h1><p>Your agency workspace</p></div></div>' +
      '<div class="tiles"><div class="card tile"><span class="k">Clients</span><span class="v">' + clients.length + '</span></div>' +
      '<div class="card tile"><span class="k">Connected accounts</span><span class="v">' + connected + '</span></div>' +
      '<div class="card tile"><span class="k">Your access</span><span class="v small">' + esc(S.workspace.isOwner ? 'Owner, full access' : S.workspace.title) + '</span></div></div>' +
      (clients.length ? '<div class="card"><div class="card-h"><h3>Clients</h3></div><div class="tw"><table><thead><tr><th>Client</th><th>Website</th><th>Site platform</th><th>Data</th></tr></thead><tbody>' +
        clients.map(function (c) { return '<tr class="row-link" data-open="' + esc(c.id) + '" tabindex="0"><td><b>' + esc(c.name) + '</b></td><td class="mono">' + esc(c.domain || '—') +
          '</td><td>' + esc(cmsLabel(c.cms)) + '</td><td><span class="pill p-warn">No accounts connected</span></td></tr>'; }).join('') + '</tbody></table></div></div>'
        : emptyClients()) +
      '<div class="notice"><b>Next for your workspace</b><span class="muted">Add your clients and team now. Connecting each client’s Google and ad accounts comes next, and their dashboards fill in from there.</span></div>';
  }
  function emptyClients() {
    return '<div class="card"><div class="empty"><b>No clients yet</b><span>' + (can('team', 'edit') ? 'Add your first client to create their workspace.' : 'Your agency hasn’t added clients yet.') + '</span>' +
      (can('team', 'edit') ? '<button class="btn btn-p" data-page="clients">Add a client</button>' : '') + '</div></div>';
  }
  function cmsLabel(c) { return { wordpress: 'WordPress', webflow: 'Webflow', other: 'Other (recommend only)' }[c] || c; }

  // Clients
  function viewClients() {
    var form = can('team', 'edit') ? '<div class="card"><div class="card-h"><h3>Add a client</h3></div><form id="cf" class="card-b" novalidate><div class="form-grid">' +
      '<div class="field"><label for="c-name">Client name</label><input id="c-name" required></div>' +
      '<div class="field"><label for="c-domain">Website</label><input id="c-domain" placeholder="example.com" inputmode="url"></div>' +
      '<div class="field"><label for="c-cms">Site platform</label><select id="c-cms"><option value="wordpress">WordPress</option><option value="webflow">Webflow</option><option value="other">Other (recommend only)</option></select></div>' +
      '</div><p class="err" id="c-err"></p><div><button class="btn btn-p" type="submit">Add client</button></div></form></div>' : '';
    return '<div class="page-head"><div><h1>Clients</h1><p>' + clients.length + ' active</p></div></div>' + form +
      (clients.length ? '<div class="card"><div class="tw"><table><thead><tr><th>Client</th><th>Website</th><th>Site platform</th></tr></thead><tbody>' +
        clients.map(function (c) { return '<tr class="row-link" data-open="' + esc(c.id) + '" tabindex="0"><td><b>' + esc(c.name) + '</b></td><td class="mono">' + esc(c.domain || '—') + '</td><td>' + esc(cmsLabel(c.cms)) + '</td></tr>'; }).join('') +
        '</tbody></table></div></div>' : '');
  }
  function wireClients() {
    if (!$('cf')) return;
    $('cf').addEventListener('submit', function (e) {
      e.preventDefault();
      api('POST', '/api/clients', { name: $('c-name').value, domain: $('c-domain').value, cms: $('c-cms').value }).then(function (r) {
        if (r.status !== 200) { $('c-err').textContent = r.data.error; return; }
        toast('Client added');
        api('GET', '/api/clients').then(function (c) { clients = c.data; render(); });
      });
    });
  }

  // One client
  function viewClient() {
    var c = clients.find(function (x) { return x.id === route.client; });
    if (!c) return '<div class="empty"><b>Client not found</b></div>';
    var tabs = CLIENT_AREAS.filter(function (a) { return can(a[0], 'view'); });
    if (!tabs.some(function (t) { return t[0] === route.tab; })) route.tab = tabs.length ? tabs[0][0] : '';
    var bodies = {
      seo: ['Search rankings and traffic', 'Connect Google Search Console and Google Analytics to see clicks, rankings and leads.'],
      site: ['Site audit and fix queue', 'The crawler runs once the site is connected' + (c.cms === 'other' ? '. On this platform fixes are sent as tasks.' : ' (' + cmsLabel(c.cms) + ' connector).')],
      ads: ['Ad spend and pacing', 'Connect Google Ads, Meta or other ad accounts to track spend, budgets and return.'],
      social: ['Content calendar', 'Connect Facebook, Instagram or Google Business Profile to plan and approve posts.'],
      reports: ['Monthly reports', 'Reports build from connected data and carry ' + S.agency.name + '’s brand.'],
      accounts: ['Connected accounts', 'Connecting Google, Meta and the website is the next build step. The client signs in to each service directly; no passwords are shared.']
    };
    var b = bodies[route.tab] || ['', ''];
    return '<div class="page-head"><div><h1>' + esc(c.name) + '</h1><p class="mono">' + esc(c.domain || 'No website set') + ' · ' + esc(cmsLabel(c.cms)) + '</p></div></div>' +
      (tabs.length ? '<div class="tabs" role="tablist">' + tabs.map(function (t) { return '<button class="tab" role="tab" data-tab="' + t[0] + '" aria-selected="' + (route.tab === t[0]) + '">' + t[1] + '</button>'; }).join('') + '</div>' +
        (route.tab === 'seo' || route.tab === 'accounts' ? '<div id="panel"><div class="card"><div class="empty"><span>Loading\u2026</span></div></div></div>'
          : '<div class="card"><div class="empty"><b>' + esc(b[0]) + '</b><span>' + esc(b[1]) + '</span><span class="pill p-warn">Waiting for connected accounts</span></div></div>')
        : '<div class="card"><div class="empty"><b>No areas available</b><span>Ask your agency for access.</span></div></div>');
  }
  function wireClient() {
    root.querySelectorAll('[data-tab]').forEach(function (b) { b.addEventListener('click', function () { route.tab = b.dataset.tab; render(); }); });
    if (route.tab === 'accounts') loadAccounts();
    if (route.tab === 'seo') loadSeo();
  }

  // Connected accounts tab
  var KIND = { search_console_site: 'Search Console site', ga4_property: 'Analytics property', meta_ad_account: 'Meta ad account', meta_page: 'Facebook page' };
  function connectGoogle() {
    api('POST', '/api/clients/' + route.client + '/connections/google', {}).then(function (r) {
      if (r.status !== 200) return toast(r.data.error);
      location.assign(r.data.url);
    });
  }
  function loadAccounts() {
    var clientId = route.client;
    api('GET', '/api/clients/' + clientId + '/connections').then(function (r) {
      if (!$('panel') || route.client !== clientId) return;
      var edit = can('accounts', 'edit');
      var list = r.status === 200 ? r.data : [];
      var head = '<div class="notice"><b>Connect this client\u2019s accounts</b><span class="muted">The account owner signs in to Google directly; no passwords are shared. Ordix only reads data (it never changes anything in Google).</span>' +
        (edit ? '<div><button class="btn btn-p" id="cg">Connect Google</button></div>' : '<span class="muted small">Ask someone with edit access to Connected accounts to connect them.</span>') + '</div>';
      var cards = list.map(function (c) {
        var st = c.status === 'connected' ? '<span class="pill p-good">Connected</span>' : '<span class="pill p-warn">Sign-in expired</span>';
        var groups = {};
        c.properties.forEach(function (p) { (groups[p.kind] = groups[p.kind] || []).push(p); });
        var props = Object.keys(groups).map(function (k) {
          return '<div class="field"><span class="small"><b>' + esc(KIND[k] || k) + '</b> <span class="muted">(feeds the dashboards)</span></span>' + groups[k].map(function (p) {
            return '<label class="row small"><input type="radio" name="' + esc(c.id + k) + '" data-prop="' + esc(p.id) + '"' + (p.selected ? ' checked' : '') + (edit ? '' : ' disabled') + '> ' + esc(p.label) + '</label>';
          }).join('') + '</div>';
        }).join('') || '<p class="muted small">This Google account has no Search Console sites or Analytics properties. Connect the account that manages them.</p>';
        return '<div class="card"><div class="card-h"><h3>Google' + (c.account ? ' \u00b7 ' + esc(c.account) : '') + '</h3><div class="row">' + st +
          (edit && c.status !== 'connected' ? '<button class="btn btn-s btn-p" data-reconnect>Reconnect</button>' : '') +
          (edit ? '<button class="btn btn-s" data-disc="' + esc(c.id) + '">Disconnect</button>' : '') + '</div></div><div class="card-b">' + props +
          '<p class="muted small">Connected by ' + esc(c.connectedBy) + ' \u00b7 ' + esc(when(c.connectedAt)) + (c.agencyApp ? ' \u00b7 using your agency\u2019s own Google app' : '') + '</p></div></div>';
      }).join('');
      $('panel').innerHTML = head + cards;
      if ($('cg')) $('cg').addEventListener('click', connectGoogle);
      root.querySelectorAll('[data-reconnect]').forEach(function (b) { b.addEventListener('click', connectGoogle); });
      root.querySelectorAll('[data-prop]').forEach(function (i) {
        i.addEventListener('change', function () { api('POST', '/api/properties/' + i.dataset.prop + '/select', {}).then(function (r) { toast(r.status === 200 ? 'Dashboards will use this one' : r.data.error); }); });
      });
      root.querySelectorAll('[data-disc]').forEach(function (b) {
        b.addEventListener('click', function () {
          if (b.dataset.sure !== '1') { b.dataset.sure = '1'; b.textContent = 'Confirm disconnect'; b.classList.add('btn-p'); return; }
          api('POST', '/api/connections/' + b.dataset.disc + '/disconnect', {}).then(function (r) { toast(r.status === 200 ? 'Disconnected. Ordix\u2019s access was removed.' : r.data.error); loadAccounts(); });
        });
      });
    });
  }

  // SEO tab
  function num(n) { return Math.round(n).toLocaleString(); }
  function loadSeo() {
    var clientId = route.client;
    api('GET', '/api/clients/' + clientId + '/seo').then(function (r) {
      if (!$('panel') || route.client !== clientId) return;
      var d = r.data || {};
      if (r.status !== 200) { $('panel').innerHTML = '<div class="card"><div class="empty"><b>' + esc(d.error) + '</b></div></div>'; return; }
      if (!d.connected) {
        $('panel').innerHTML = '<div class="card"><div class="empty"><b>Search rankings and traffic</b><span>Connect Google Search Console and Analytics to see clicks, rankings and leads.</span>' +
          (can('accounts', 'view') ? '<button class="btn btn-p" data-tab-go="accounts">Go to Connected accounts</button>' : '') + '</div></div>';
        var g = root.querySelector('[data-tab-go]'); if (g) g.addEventListener('click', function () { route.tab = 'accounts'; render(); });
        return;
      }
      if (d.error) { $('panel').innerHTML = '<div class="card"><div class="empty"><b>' + esc(d.error) + '</b>' + (d.reconnect ? '<span>Reconnect the Google account in Connected accounts.</span>' : '') + '</div></div>'; return; }
      var t = d.totals, a = d.analytics, html = '<div class="tiles">';
      if (t) {
        var ch = t.clicksPrev ? Math.round((t.clicks - t.clicksPrev) / t.clicksPrev * 100) : null;
        html += '<div class="card tile"><span class="k">Clicks from Google, last 28 days</span><span class="v">' + num(t.clicks) + '</span><span class="small ' + (ch === null ? 'muted' : ch >= 0 ? 'up' : 'down') + '">' +
          (ch === null ? 'No earlier period yet' : (ch >= 0 ? '\u25b2 ' : '\u25bc ') + Math.abs(ch) + '% vs prior 28 days') + '</span></div>' +
          '<div class="card tile"><span class="k">Times shown in Google</span><span class="v">' + num(t.impressions) + '</span><span class="small muted">impressions, last 28 days</span></div>' +
          '<div class="card tile"><span class="k">Average position</span><span class="v">' + (t.position ? t.position.toFixed(1) : '\u2014') + '</span><span class="small muted">lower is better</span></div>';
      }
      if (a) html += '<div class="card tile"><span class="k">Website sessions, last 28 days</span><span class="v">' + num(a.sessions) + '</span><span class="small muted">' + num(a.keyEvents) + ' key events (leads, calls, forms)</span></div>';
      html += '</div>';
      if (d.weeks) html += '<div class="card"><div class="card-h"><h3>Clicks from Google by week</h3><span class="muted small">' + esc(d.site) + ' \u00b7 through ' + esc(new Date(d.through + 'T12:00').toLocaleDateString([], { month: 'short', day: 'numeric' })) + '</span></div><div class="card-b">' + lineChart(d.weeks) + '</div></div>';
      if (d.queries && d.queries.length) html += table('Top searches, last 28 days', ['Search', 'Clicks', 'Shown', 'Position'], d.queries.map(function (x) { return [esc(x.query), num(x.clicks), num(x.impressions), x.position.toFixed(1)]; }));
      if (d.pages && d.pages.length) html += table('Top pages, last 28 days', ['Page', 'Clicks', 'Shown', 'Position'], d.pages.map(function (x) { return ['<span class="mono small">' + esc(x.page.replace(/^https?:\/\/[^/]+/, '') || '/') + '</span>', num(x.clicks), num(x.impressions), x.position.toFixed(1)]; }));
      if (a && !d.weeks) html += '<p class="muted small">Pick a Search Console site in Connected accounts to see searches and rankings.</p>';
      $('panel').innerHTML = html;
      wireChart();
    });
  }
  function table(title, cols, rows) {
    return '<div class="card"><div class="card-h"><h3>' + esc(title) + '</h3></div><div class="tw"><table><thead><tr>' + cols.map(function (c, i) { return '<th' + (i ? ' class="num"' : '') + '>' + c + '</th>'; }).join('') +
      '</tr></thead><tbody>' + rows.map(function (r) { return '<tr>' + r.map(function (c, i) { return '<td' + (i ? ' class="num"' : '') + '>' + c + '</td>'; }).join('') + '</tr>'; }).join('') + '</tbody></table></div></div>';
  }
  function lineChart(weeks) {
    var W = 960, H = 260, L = 52, R = 16, T = 12, B = 30, vals = weeks.map(function (w) { return w.clicks; });
    var step = Math.max(1, Math.ceil(Math.max.apply(null, vals.concat([4])) / 4 / 10) * 10), mx = step * 4;
    var x = function (i) { return L + i * (W - L - R) / (vals.length - 1); }, y = function (v) { return T + (1 - v / mx) * (H - T - B); };
    var g = '', i;
    for (i = 0; i <= 4; i++) g += '<line class="grid" x1="' + L + '" x2="' + (W - R) + '" y1="' + y(step * i) + '" y2="' + y(step * i) + '"/><text x="' + (L - 8) + '" y="' + (y(step * i) + 4) + '" text-anchor="end">' + num(step * i) + '</text>';
    for (i = 0; i < weeks.length; i += 3) g += '<text x="' + x(i) + '" y="' + (H - 8) + '" text-anchor="middle">' + esc(new Date(weeks[i].weekEnding + 'T12:00').toLocaleDateString([], { month: 'short', day: 'numeric' })) + '</text>';
    var pts = vals.map(function (v, i) { return x(i).toFixed(1) + ',' + y(v).toFixed(1); });
    var hits = vals.map(function (v, i) { var w = (W - L - R) / (vals.length - 1); return '<rect data-i="' + i + '" x="' + (x(i) - w / 2) + '" y="' + T + '" width="' + w + '" height="' + (H - T - B) + '" fill="transparent"/>'; }).join('');
    return '<div class="chart-wrap" data-weeks="' + esc(JSON.stringify(weeks)) + '"><svg class="chart" viewBox="0 0 ' + W + ' ' + H + '" role="img" aria-label="Clicks from Google by week, last 12 weeks">' + g +
      '<path class="area" d="M' + x(0) + ',' + y(0) + ' L' + pts.join(' L') + ' L' + x(vals.length - 1) + ',' + y(0) + ' Z"/><polyline class="line" points="' + pts.join(' ') + '"/>' +
      '<circle class="dot" cx="' + x(vals.length - 1) + '" cy="' + y(vals[vals.length - 1]) + '" r="4.5"/><line class="cross" y1="' + T + '" y2="' + (H - B) + '" visibility="hidden"/>' + hits + '</svg><div class="tip" hidden></div></div>';
  }
  function wireChart() {
    root.querySelectorAll('.chart-wrap').forEach(function (wrap) {
      var weeks = JSON.parse(wrap.dataset.weeks), svg = wrap.querySelector('svg'), tip = wrap.querySelector('.tip'), cross = svg.querySelector('.cross');
      svg.querySelectorAll('rect[data-i]').forEach(function (rect) {
        rect.addEventListener('mouseenter', function () {
          var i = +rect.dataset.i, p = svg.querySelector('.line').getAttribute('points').split(' ')[i].split(','), sx = svg.getBoundingClientRect().width / 960;
          cross.setAttribute('x1', p[0]); cross.setAttribute('x2', p[0]); cross.setAttribute('visibility', 'visible');
          tip.style.left = (p[0] * sx) + 'px'; tip.style.top = (p[1] * sx) + 'px';
          tip.textContent = 'Week ending ' + new Date(weeks[i].weekEnding + 'T12:00').toLocaleDateString([], { month: 'short', day: 'numeric' }) + ': ' + num(weeks[i].clicks) + ' clicks'; tip.hidden = false;
        });
      });
      svg.addEventListener('mouseleave', function () { cross.setAttribute('visibility', 'hidden'); tip.hidden = true; });
    });
  }

  // Team
  function loadTeam() {
    api('GET', '/api/team').then(function (r) {
      if (r.status !== 200) return shell('<div class="empty"><b>' + esc(r.data.error) + '</b></div>');
      shell(viewTeam(r.data)); wireTeam(r.data);
    });
  }
  function viewTeam(team) {
    var edit = can('team', 'edit');
    var head = '<tr><th>Person</th><th>Works on</th>' + AREAS.map(function (a) { return '<th>' + a[1] + '</th>'; }).join('') + '<th>Status</th></tr>';
    var rows = team.map(function (m) {
      var cells = AREAS.map(function (a) {
        var lvl = m.access[a[0]];
        var locked = !edit || m.isOwner || !m.active || (m.clientId && AGENCY_ONLY.indexOf(a[0]) >= 0);
        if (locked) return '<td>' + (lvl === 'none' ? '<span class="muted">none</span>' : esc(lvl)) + '</td>';
        return '<td><select class="inline" aria-label="' + esc(m.name + ': ' + a[1]) + '" data-acc="' + esc(m.id) + '" data-mod="' + a[0] + '">' +
          LEVELS.map(function (l) { return '<option' + (l === lvl ? ' selected' : '') + '>' + l + '</option>'; }).join('') + '</select></td>';
      }).join('');
      var status = m.isOwner ? '<span class="pill p-info">Owner</span>' : !edit || m.id === S.workspace.membershipId ? (m.active ? '<span class="pill p-good">Active</span>' : '<span class="pill">Inactive</span>')
        : '<button class="btn btn-s" data-active="' + esc(m.id) + '" data-to="' + (!m.active) + '">' + (m.active ? 'Deactivate' : 'Reactivate') + '</button>';
      return '<tr><td><b>' + esc(m.name) + '</b><div class="muted small">' + esc(m.title) + ' · ' + esc(m.email) + '</div></td><td>' + esc(m.client || 'Agency') + '</td>' + cells + '<td>' + status + '</td></tr>';
    }).join('');
    var tpl = S.templates.map(function (t) { return '<option value="' + esc(t.key) + '" data-client-level="' + t.clientLevel + '">' + esc(t.title) + (t.clientLevel ? ' (client team)' : '') + '</option>'; }).join('');
    var form = edit ? '<div class="card"><div class="card-h"><h3>Add a person</h3><span class="muted small">Pick a starting role; adjust any area afterwards</span></div><form id="tf" class="card-b" novalidate><div class="form-grid">' +
      '<div class="field"><label for="t-name">Full name</label><input id="t-name" autocomplete="off"></div>' +
      '<div class="field"><label for="t-email">Email</label><input id="t-email" type="email" autocomplete="off"></div>' +
      '<div class="field"><label for="t-role">Starting role</label><select id="t-role">' + tpl + '</select></div>' +
      '<div class="field" id="t-client-f" hidden><label for="t-client">Client</label><select id="t-client">' + clients.map(function (c) { return '<option value="' + esc(c.id) + '">' + esc(c.name) + '</option>'; }).join('') + '</select></div>' +
      '</div><p class="err" id="t-err"></p><div><button class="btn btn-p" type="submit">Add person</button></div><div id="t-pass"></div></form></div>' : '';
    return '<div class="page-head"><div><h1>Team and access</h1><p>Each person gets none, view, edit or approve for each area. Client teams never see margins, team or branding.</p></div></div>' +
      form + '<div class="card"><div class="tw"><table><thead>' + head + '</thead><tbody>' + rows + '</tbody></table></div></div>';
  }
  function wireTeam() {
    root.querySelectorAll('[data-acc]').forEach(function (s) {
      s.addEventListener('change', function () {
        api('POST', '/api/team/' + s.dataset.acc + '/access', { module: s.dataset.mod, level: s.value }).then(function (r) {
          toast(r.status === 200 ? 'Access updated' : r.data.error); if (r.status !== 200) loadTeam();
        });
      });
    });
    root.querySelectorAll('[data-active]').forEach(function (b) {
      b.addEventListener('click', function () {
        api('POST', '/api/team/' + b.dataset.active + '/active', { active: b.dataset.to === 'true' }).then(function (r) { toast(r.status === 200 ? 'Saved' : r.data.error); loadTeam(); });
      });
    });
    if (!$('tf')) return;
    var syncClient = function () { $('t-client-f').hidden = $('t-role').selectedOptions[0].dataset.clientLevel !== 'true'; };
    $('t-role').addEventListener('change', syncClient); syncClient();
    $('tf').addEventListener('submit', function (e) {
      e.preventDefault();
      var clientLevel = !$('t-client-f').hidden;
      if (clientLevel && !clients.length) { $('t-err').textContent = 'Add a client first'; return; }
      api('POST', '/api/team', { fullName: $('t-name').value, email: $('t-email').value, template: $('t-role').value, clientId: clientLevel ? $('t-client').value : '' }).then(function (r) {
        if (r.status !== 200) { $('t-err').textContent = r.data.error; return; }
        var email = $('t-email').value;
        loadTeam();
        setTimeout(function () {
          if (!$('t-pass')) return;
          $('t-pass').innerHTML = r.data.temporaryPassword
            ? '<div class="notice"><b>Send these sign-in details to ' + esc(email) + '</b><span>Temporary password, shown once:</span><p class="secret">' + esc(r.data.temporaryPassword) +
              '</p><span class="muted small">They’ll set up an authenticator app and choose their own password at first sign-in.</span></div>'
            : '<div class="notice"><b>' + esc(email) + ' already has a sign-in</b><span class="muted">They’ll see your agency as a workspace the next time they sign in.</span></div>';
        }, 300);
      });
    });
  }

  // Branding
  function viewBranding() {
    var colors = ['#0A7A6A', '#2557C9', '#6E3FA8', '#B4322A', '#B86E00', '#1F2937'];
    return '<div class="page-head"><div><h1>Branding</h1><p>What your clients see: the portal, reports and emails carry your name and color, never Ordix.</p></div></div>' +
      '<div class="card"><form id="bf" class="card-b" novalidate>' +
      '<div class="field"><label for="b-name">Agency name</label><input id="b-name" value="' + esc(S.agency.name) + '"></div>' +
      '<div class="field"><label for="b-portal">Portal address (optional)</label><input id="b-portal" placeholder="portal.youragency.com" value="' + esc(S.agency.portalDomain || '') + '"></div>' +
      '<div class="field"><span class="small"><b>Brand color</b></span><div class="swatches">' + colors.map(function (c) {
        return '<button type="button" class="sw" data-color="' + c + '" aria-label="Use ' + c + '" aria-pressed="' + (c.toLowerCase() === S.agency.brandColor.toLowerCase()) + '"></button>'; }).join('') + '</div></div>' +
      '<p class="err" id="b-err"></p><div><button class="btn btn-p" type="submit">Save branding</button></div></form></div>';
  }
  function wireBranding() {
    var color = S.agency.brandColor;
    root.querySelectorAll('.sw').forEach(function (b) {
      b.style.background = b.dataset.color;
      b.addEventListener('click', function () {
        color = b.dataset.color; setBrand(color);
        root.querySelectorAll('.sw').forEach(function (x) { x.setAttribute('aria-pressed', String(x === b)); });
      });
    });
    $('bf').addEventListener('submit', function (e) {
      e.preventDefault();
      api('POST', '/api/agency/branding', { name: $('b-name').value, brandColor: color, portalDomain: $('b-portal').value }).then(function (r) {
        if (r.status !== 200) { $('b-err').textContent = r.data.error; return; }
        toast('Branding saved'); loadApp();
      });
    });
  }

  // Activity
  function loadActivity() {
    api('GET', '/api/activity').then(function (r) {
      if (r.status !== 200) return shell('<div class="empty"><b>' + esc(r.data.error) + '</b></div>');
      shell('<div class="page-head"><div><h1>Activity log</h1><p>Every change in your agency, with who made it. Entries can’t be edited or deleted.</p></div></div>' +
        '<div class="card"><div class="card-b"><ul class="log">' + (r.data.length ? r.data.map(function (a) {
          return '<li><span class="muted small">' + esc(when(a.at)) + '</span><span><b>' + esc(a.actor) + '</b> · ' + esc(describe(a)) + '</span></li>'; }).join('')
          : '<li><span></span><span class="muted">No activity yet</span></li>') + '</ul></div></div>');
    });
  }
  function describe(a) {
    var what = { clients: 'client', memberships: 'team member', agencies: 'agency', membership_access: 'access', people: 'person' }[a.entity] || a.entity;
    var area = (AREAS.find(function (x) { return x[0] === a.module; }) || [0, a.module])[1];
    if (a.entity === 'membership_access') return 'Set ' + (a.label ? a.label + '\u2019s ' : '') + area + ' access to ' + a.level;
    if (a.entity === 'memberships' && a.action === 'insert') return 'Added ' + (a.label || 'a person') + (a.title ? ' as ' + a.title : '');
    if (a.action === 'insert') return 'Added ' + what + (a.label ? ': ' + a.label : '');
    if (a.action === 'delete') return 'Removed ' + what + (a.label ? ': ' + a.label : '');
    return 'Changed ' + what + (a.label ? ' ' + a.label : '') + (a.changed && a.changed.length ? ' (' + a.changed.join(', ').replace(/_/g, ' ') + ')' : '');
  }

  // Open a client from any table row.
  document.addEventListener('click', function (e) {
    var row = e.target.closest('[data-open]');
    if (row) { route.page = 'client'; route.client = row.dataset.open; route.tab = 'seo'; render(); window.scrollTo(0, 0); }
  });
  document.addEventListener('keydown', function (e) { if (e.key === 'Enter' && e.target.dataset && e.target.dataset.open) e.target.click(); });

  // Start
  api('GET', '/auth/me').then(function (r) { if (r.status !== 200) return showSignIn(); afterSignIn(r.data); });
})();
