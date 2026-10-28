// @ts-check
// AegisNet web console. Dependency-free; served by the gateway under a strict
// CSP (no inline script or style, no remote assets). All dynamic text is
// inserted with textContent, never innerHTML.
"use strict";

/** @type {{csrf: string|null, principal: string|null, username: string, roles: string[], scopes: string[]}} */
const session = { csrf: null, principal: null, username: "", roles: [], scopes: [] };
let currentView = "";
/** Served as the user portal (under /portal on the public device address)? */
const PORTAL = location.pathname === "/portal" || location.pathname.startsWith("/portal/");
const BASE = PORTAL ? "/portal" : "";
/** @type {string|null} The portal address users sign in at (console only). */
let portalUrl = null;
/** @type {number|undefined} */
let pollTimer;

// ---------------------------------------------------------------- helpers

/** @param {string} tag @param {Record<string,string>} [attrs] @param {(Node|string|null|undefined|false)[]} [children] */
function el(tag, attrs = {}, children = []) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") e.className = v;
    else e.setAttribute(k, v);
  }
  for (const c of children) {
    if (c == null || c === false) continue;
    e.append(typeof c === "string" ? document.createTextNode(c) : c);
  }
  return e;
}

/** @param {string} msg @param {boolean} [isError] */
function notice(msg, isError = false) {
  const n = /** @type {HTMLElement} */ (document.getElementById("notice"));
  n.textContent = msg;
  n.className = isError ? "err" : msg ? "ok" : "";
  if (msg && !isError) setTimeout(() => { if (n.textContent === msg) { n.textContent = ""; n.className = ""; } }, 6000);
}

function randomKey() {
  const b = new Uint8Array(18);
  crypto.getRandomValues(b);
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

/** @param {string} s */
const can = (s) => session.scopes.includes(s);

/**
 * Same-origin API call. Cookie-authenticated mutations carry X-CSRF-Token.
 * @param {string} method @param {string} path
 * @param {{body?: any, headers?: Record<string,string>, contentType?: string}} [opts]
 */
async function api(method, path, opts = {}) {
  /** @type {Record<string,string>} */
  const headers = { Accept: "application/json", ...(opts.headers || {}) };
  if (method !== "GET" && session.csrf) headers["X-CSRF-Token"] = session.csrf;
  let body;
  if (opts.body !== undefined) {
    headers["Content-Type"] = opts.contentType || "application/json";
    body = JSON.stringify(opts.body);
  }
  const resp = await fetch(BASE + "/api/v1" + path, { method, headers, body, credentials: "same-origin", cache: "no-store" });
  const text = await resp.text();
  /** @type {any} */
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = null; }
  if (resp.status === 401 && path !== "/auth/login" && path !== "/auth/me") {
    showLogin("Your session ended. Sign in again.");
    throw new Error("signed out");
  }
  if (!resp.ok) {
    const code = data && data.aegis_error_code ? data.aegis_error_code : String(resp.status);
    const detail = data && data.detail ? data.detail : "";
    const err = new Error(detail ? detail : friendly(code));
    // @ts-ignore
    err.status = resp.status;
    // @ts-ignore
    err.code = code;
    throw err;
  }
  return { data, etag: resp.headers.get("ETag"), status: resp.status };
}

/** @param {string} code */
function friendly(code) {
  /** @type {Record<string,string>} */
  const m = {
    unauthenticated: "Incorrect username or password.",
    forbidden: "You do not have permission to do that.",
    rate_limited: "Too many attempts. Wait a few minutes and try again.",
    weak_password: "Choose a password with at least 12 characters.",
    stale_etag: "Someone else changed this in the meantime. Reload and try again.",
    storage_unavailable: "The server is busy. Try again.",
  };
  return m[code] || code.replace(/_/g, " ");
}

/** @param {unknown} e */
const msg = (e) => String(/** @type {Error} */ (e).message || e);

/** @param {string} text */
async function copy(text) {
  try {
    await navigator.clipboard.writeText(text);
    notice("Copied to the clipboard.");
  } catch {
    notice("Copy failed: select the text and copy it manually.", true);
  }
}

/** @param {string} name @param {string} text @param {string} [type] */
function download(name, text, type = "text/plain") {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = el("a", { href: url, download: name });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/** @param {string|null|undefined} iso */
function when(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  return isNaN(d.getTime()) ? iso : d.toLocaleString();
}

/** @param {string|null|undefined} iso */
function inDays(iso) {
  if (!iso) return null;
  return Math.round((new Date(iso).getTime() - Date.now()) / 86400000);
}

/** @param {string} title @param {(Node|string|null|undefined|false)[]} children @param {string} [cls] */
function card(title, children, cls = "") {
  return el("section", { class: "card " + cls }, [title ? el("h2", {}, [title]) : null, ...children]);
}

/** @param {string} label @param {HTMLElement} input @param {string} [help] */
function field(label, input, help) {
  const id = input.id || "f" + randomKey().slice(0, 8);
  input.id = id;
  return el("div", { class: "field" }, [el("label", { for: id }, [label]), input, help ? el("div", { class: "help" }, [help]) : null]);
}

/** @param {string} text @param {string} [cls] @param {string} [type] */
function button(text, cls = "", type = "button") {
  return /** @type {HTMLButtonElement} */ (el("button", { type, class: cls }, [text]));
}

/** @param {HTMLButtonElement} b @param {() => Promise<void>} fn */
function busy(b, fn) {
  b.addEventListener("click", async () => {
    if (b.disabled) return;
    b.disabled = true;
    b.classList.add("busy");
    try { await fn(); } catch (e) { if (msg(e) !== "signed out") notice(msg(e), true); }
    finally { b.disabled = false; b.classList.remove("busy"); }
  });
}

/** @param {string} k @param {any} v @param {string} [cls] */
function stat(k, v, cls = "") {
  return el("div", { class: "stat " + cls }, [el("div", { class: "v" }, [v == null ? "—" : String(v)]), el("div", { class: "k" }, [k])]);
}

/** @param {string} state */
function pill(state) {
  const s = String(state);
  const cls = /^(active|ready|ok|running|allowed|connected)/.test(s) || s.startsWith("ok ") ? "ok"
    : /^(failed|error|revoked|disabled|denied|recovery_required)/.test(s) || s.startsWith("expires in") ? "bad"
    : /^(applying|issuing|pending|planned|planning|removing|starting|verifying|must change)/.test(s) ? "warn" : "";
  return el("span", { class: "pill " + cls }, [state]);
}

function root() {
  if (pollTimer) { clearTimeout(pollTimer); pollTimer = undefined; }
  const v = /** @type {HTMLElement} */ (document.getElementById("view"));
  v.replaceChildren();
  return v;
}

// ---------------------------------------------------------------- navigation

/** @returns {[string, string][]} */
function sections() {
  /** @type {[string, string][]} */
  const s = [];
  if (can("profiles:read")) s.push(["overview", "Overview"]);
  if (can("devices:self") || can("nodes:read")) s.push(["devices", can("nodes:read") ? "Devices" : "My devices"]);
  if (can("users:manage")) s.push(["users", "Users"]);
  if (can("system:configure")) s.push(["connectivity", "Connectivity"]);
  if (can("provision:read")) s.push(["integrations", "Integrations"]);
  if (can("diagnostics:explain")) s.push(["diagnostics", "Diagnostics"]);
  if (can("profiles:read")) s.push(["configuration", "Advanced configuration"]);
  if (can("audit:read")) s.push(["audit", "Audit log"]);
  s.push(["account", "Account"]);
  return s;
}

function buildNav() {
  const nav = /** @type {HTMLElement} */ (document.getElementById("nav"));
  nav.replaceChildren(...sections().map(([id, label]) => {
    const b = el("button", { type: "button", "data-view": id, "aria-current": "false" }, [label]);
    b.addEventListener("click", () => view(id));
    return b;
  }));
  nav.hidden = false;
}

/** @param {string} id */
function view(id) {
  currentView = id;
  try { history.replaceState(null, "", "#" + id); } catch { /* ignore */ }
  for (const b of document.querySelectorAll("#nav button")) {
    b.setAttribute("aria-current", String(b.getAttribute("data-view") === id));
  }
  notice("");
  render().catch((e) => { if (msg(e) !== "signed out") notice(msg(e), true); });
}

async function render() {
  /** @type {Record<string, () => Promise<void>>} */
  const views = {
    overview: renderOverview, devices: renderDevices, users: renderUsers,
    connectivity: renderConnectivity, integrations: renderIntegrations,
    configuration: renderConfiguration, diagnostics: renderDiagnostics, audit: renderAudit, account: renderAccount,
  };
  const fn = views[currentView] || renderAccount;
  await fn();
}

// ---------------------------------------------------------------- auth

async function boot() {
  try {
    const { data } = await api("GET", "/auth/me");
    adopt(data);
  } catch {
    showLogin();
  }
}

/** @param {any} data */
function adopt(data) {
  session.csrf = data.csrf_token;
  session.principal = data.principal_id;
  session.username = data.username || "";
  session.roles = data.roles || [];
  session.scopes = data.scopes || [];
  const who = /** @type {HTMLElement} */ (document.getElementById("who"));
  who.textContent = session.username + (session.roles.length ? " · " + session.roles.join(", ") : "");
  who.hidden = false;
  /** @type {HTMLElement} */ (document.getElementById("logout")).hidden = false;
  if (data.password_change_required) {
    /** @type {HTMLElement} */ (document.getElementById("nav")).hidden = true;
    showForcedChange();
    return;
  }
  buildNav();
  const wanted = location.hash.replace("#", "");
  const ids = sections().map((s) => s[0]);
  view(ids.includes(wanted) ? wanted : ids[0]);
}

/** @param {string} [why] */
function showLogin(why) {
  /** @type {HTMLElement} */ (document.getElementById("nav")).hidden = true;
  /** @type {HTMLElement} */ (document.getElementById("logout")).hidden = true;
  /** @type {HTMLElement} */ (document.getElementById("who")).hidden = true;
  /** @type {HTMLElement} */ (document.getElementById("badges")).replaceChildren();
  session.csrf = null; session.scopes = [];
  const v = root();
  const user = /** @type {HTMLInputElement} */ (el("input", { autocomplete: "username", required: "", value: PORTAL ? "" : "admin" }));
  const pass = /** @type {HTMLInputElement} */ (el("input", { type: "password", autocomplete: "current-password", required: "" }));
  const submit = button("Sign in", "", "submit");
  const form = el("form", { class: "card narrow", "aria-labelledby": "lh" }, [
    el("h1", { id: "lh" }, ["Sign in"]),
    why ? el("p", { class: "muted" }, [why]) : null,
    field("Username", user),
    field("Password", pass, PORTAL
      ? "First sign-in? Use the one-time password your administrator gave you; you will choose your own."
      : "First sign-in? The installer printed a one-time admin password (also readable with `aegisctl initial-password` on the server)."),
  ]);
  // Second step, shown when the account uses two-factor authentication.
  const code = /** @type {HTMLInputElement} */ (el("input", { autocomplete: "one-time-code", inputmode: "numeric", spellcheck: "false" }));
  const codeField = field("Authentication code", code, "The 6-digit code from your authenticator app, or one of your recovery codes.");
  codeField.hidden = true;
  form.append(codeField, el("div", { class: "row" }, [submit]));
  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    submit.disabled = true;
    try {
      /** @type {Record<string,string>} */
      const body = { username: user.value.trim(), password: pass.value };
      if (!codeField.hidden && code.value.trim()) body.code = code.value.trim();
      const { data } = await api("POST", "/auth/login", { body });
      pass.value = ""; code.value = "";
      adopt(data);
    } catch (e) {
      // @ts-ignore
      if (e.code === "two_factor_required") {
        codeField.hidden = false;
        notice("Enter the code from your authenticator app.");
        code.focus();
      } else {
        notice(msg(e), true);
      }
    } finally {
      submit.disabled = false;
    }
  });
  v.append(form);
  if (PORTAL) {
    v.append(el("p", { class: "muted small narrow" }, ["This is the AegisNet user portal: add your devices, remove old ones and download the app. Administrators sign in with two-factor authentication."]));
  } else {
    v.append(bootstrapCard());
  }
  (session.username ? pass : user).focus();
}

/** Legacy first-run for hand-configured nodes (no appliance password). */
function bootstrapCard() {
  const tok = /** @type {HTMLInputElement} */ (el("input", { autocomplete: "off" }));
  const ou = /** @type {HTMLInputElement} */ (el("input", { autocomplete: "username" }));
  const op = /** @type {HTMLInputElement} */ (el("input", { type: "password", autocomplete: "new-password", minlength: "12" }));
  const submit = button("Create owner", "ghost", "submit");
  const claim = el("form", { class: "card narrow" }, [
    el("h2", {}, ["Hand-configured node without an owner?"]),
    el("p", { class: "muted" }, ["Create the owner with the one-time token from `aegisctl bootstrap-token` on the server."]),
    field("Bootstrap token", tok), field("Owner username", ou), field("Owner password (12+ characters)", op),
    el("div", { class: "row" }, [submit]),
  ]);
  const details = el("details", { class: "narrow" }, [el("summary", {}, ["Other setup options"]), claim]);
  claim.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    try {
      await api("POST", "/bootstrap/claim", { body: { bootstrap_token: tok.value, owner_username: ou.value, owner_password: op.value } });
      tok.value = ""; op.value = "";
      notice("Owner created. Sign in above.");
    } catch (e) { notice(msg(e), true); }
  });
  return details;
}

function passwordForm(/** @type {boolean} */ forced) {
  const cur = /** @type {HTMLInputElement} */ (el("input", { type: "password", autocomplete: "current-password", required: "" }));
  const next = /** @type {HTMLInputElement} */ (el("input", { type: "password", autocomplete: "new-password", required: "", minlength: "12" }));
  const again = /** @type {HTMLInputElement} */ (el("input", { type: "password", autocomplete: "new-password", required: "", minlength: "12" }));
  const meter = el("div", { class: "help" }, ["At least 12 characters. A passphrase of several words works well."]);
  next.addEventListener("input", () => {
    const n = next.value.length;
    meter.textContent = n === 0 ? "At least 12 characters." : n < 12 ? (12 - n) + " more characters needed." : "Length OK.";
    meter.className = "help " + (n >= 12 ? "good" : "");
  });
  const submit = button(forced ? "Set password and continue" : "Change password", "", "submit");
  const form = el("form", { class: "card narrow" }, [
    el("h1", {}, [forced ? "Choose your own password" : "Change password"]),
    forced ? el("p", { class: "muted" }, ["For security, the generated password must be replaced before you continue. All other sessions will be signed out."]) : null,
    field(forced ? "Current (generated) password" : "Current password", cur),
    field("New password", next),
    meter,
    field("Repeat new password", again),
    el("div", { class: "row" }, [submit]),
  ]);
  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    if (next.value !== again.value) { notice("The new passwords do not match.", true); return; }
    submit.disabled = true;
    try {
      const { data } = await api("POST", "/auth/password", { body: { current_password: cur.value, new_password: next.value } });
      cur.value = next.value = again.value = "";
      notice("Password changed.");
      adopt(data);
    } catch (e) {
      notice(msg(e), true);
    } finally { submit.disabled = false; }
  });
  return { form, focus: () => cur.focus() };
}

function showForcedChange() {
  const v = root();
  const f = passwordForm(true);
  v.append(f.form);
  f.focus();
}

// ---------------------------------------------------------------- overview

async function renderOverview() {
  const v = root();
  const [{ data: info }, { data: h }] = await Promise.all([api("GET", "/system/info"), api("GET", "/system/health")]);
  const badges = /** @type {HTMLElement} */ (document.getElementById("badges"));
  badges.replaceChildren(
    el("span", { class: "badge " + (h.status === "ready" ? "ok" : h.status === "degraded" ? "bad" : "warn") }, [h.status === "ready" ? "Gateway ready" : "Gateway " + h.status]),
    el("span", { class: "badge " + (h.admission_enabled ? "ok" : "bad") }, [h.admission_enabled ? "Accepting devices" : "Admission held"]),
  );
  const c = info.checklist || {};
  const conn = info.connection || {};
  /** @param {boolean} done @param {string} title @param {string} detail @param {string} [go] @param {string} [goLabel] */
  const step = (done, title, detail, go, goLabel) => {
    const b = go && !done ? button(goLabel || "Open", "small") : null;
    if (b && go) b.addEventListener("click", () => view(go));
    return el("li", { class: done ? "done" : "todo" }, [
      el("span", { class: "tick", "aria-hidden": "true" }, [done ? "✓" : "•"]),
      el("div", {}, [el("strong", {}, [title]), el("div", { class: "muted" }, [detail])]),
      b,
    ]);
  };
  const steps = el("ol", { class: "checklist" }, [
    step(!!c.owner_password_changed, "Secure the admin account", "Replace the generated password.", "account", "Change password"),
    step(!!c.server_address_set, "Tell devices how to reach this server",
      conn.public_host ? "Devices connect to " + conn.public_host + (conn.public_port && conn.public_port !== 443 ? ":" + conn.public_port : "") + (conn.mode && conn.mode !== "direct" ? " via " + conn.mode : "") : "Set the server address, or connect a Cloudflare Tunnel for access from anywhere.",
      "connectivity", "Set up connectivity"),
    step((c.devices_enrolled || 0) > 0, "Add your first device", (c.devices_enrolled || 0) + " device(s) enrolled. Create an invitation and paste it into the AegisNet client app.", "devices", "Invite a device"),
  ]);
  if (info.runtime && info.runtime.certificates && info.runtime.certificates.issuer_renewal_due) {
    const go = button("Renew the device issuer", "small");
    go.addEventListener("click", () => view("account"));
    v.append(card("Device issuer expires soon", [
      el("p", {}, ["The device root key is offline, so the issuer that signs device certificates can't renew by itself. Renew it with the root key file, or devices will stop being able to join and renew."]),
      el("div", { class: "row" }, [go]),
    ], "warn-card"));
  }
  v.append(card("Getting started", [steps]));

  const rt = info.runtime || {};
  const certs = rt.certificates || {};
  /** @param {string} label @param {string|undefined} iso */
  const certRow = (label, iso) => {
    const d = inDays(iso);
    return el("tr", {}, [el("th", {}, [label]), el("td", {}, [when(iso)]), el("td", {}, [d == null ? "" : pill(d < 7 ? "expires in " + d + " days" : "ok · " + d + " days")])]);
  };
  v.append(card("Status", [
    el("div", { class: "grid" }, [
      stat("Gateway", h.status),
      stat("Version", info.version),
      stat("Devices", c.devices_enrolled),
      stat("Connection", conn.mode || "not set"),
    ]),
    info.appliance ? el("table", { class: "kv" }, [el("tbody", {}, [
      certRow("Gateway identity", certs.gateway_identity_expires_at),
      certRow("Device issuer", certs.issuer_expires_at),
      certRow("Edge certificate", certs.edge_expires_at),
      certRow("Console certificate", certs.console_expires_at),
    ])]) : null,
    info.appliance ? el("p", { class: "muted" }, [certs.root_key_on_host ? "Certificates renew automatically. The device root key is stored on this server." : "Certificates renew automatically, except the device issuer: the device root key is offline, so renew the issuer under Account before it expires."]) : null,
    info.console_certificate_sha256 ? el("p", { class: "muted small" }, ["Console certificate SHA-256: ", el("span", { class: "mono" }, [info.console_certificate_sha256])]) : null,
  ]));
  if (can("telemetry:read")) {
    try {
      const { data } = await api("GET", "/system/metrics");
      const m = data.metrics;
      v.append(card("Traffic (local counters, never exported)", [el("div", { class: "grid" }, [
        stat("Active sessions", m.gauges.sessions_active),
        stat("Active streams", m.gauges.streams_active),
        stat("Streams opened", m.streams_opened),
        stat("Sent to devices", fmtBytes(m.transport_bytes_up)),
        stat("Received from devices", fmtBytes(m.transport_bytes_down)),
      ])]));
    } catch { /* optional */ }
  }
}

/** @param {number|undefined} n */
function fmtBytes(n) {
  if (n == null) return "—";
  const u = ["B", "KB", "MB", "GB", "TB"];
  let i = 0; let x = n;
  while (x >= 1024 && i < u.length - 1) { x /= 1024; i++; }
  return (i ? x.toFixed(1) : String(x)) + " " + u[i];
}

// ---------------------------------------------------------------- devices

async function renderDevices() {
  const v = root();
  const all = can("nodes:read");
  if (can("devices:self")) v.append(inviteCard());
  v.append(await downloadsCard());
  const { data } = await api("GET", "/devices" + (all ? "?scope=all" : ""));
  const rows = data.items.map((/** @type {any} */ n) => {
    const revoke = button("Revoke", "danger small");
    revoke.disabled = n.status === "revoked";
    busy(revoke, async () => {
      if (!confirm("Revoke " + n.name + "? It is disconnected immediately and can never connect again with its current identity.")) return;
      await api("POST", "/devices/" + n.id + "/revoke", { headers: { "If-Match": n.etag, "Idempotency-Key": randomKey() } });
      notice(n.name + " revoked.");
      setTimeout(() => view("devices"), 700);
    });
    const d = inDays(n.certificate_expires_at);
    return el("tr", {}, [
      el("td", {}, [el("strong", {}, [n.name])]),
      el("td", {}, [pill(n.status)]),
      el("td", {}, [when(n.created_at)]),
      el("td", {}, [n.status === "revoked" ? "—" : d == null ? "—" : d + " days (auto-renews)"]),
      el("td", {}, [revoke]),
    ]);
  });
  v.append(card(all ? "All devices" : "My devices", [
    rows.length
      ? el("table", {}, [el("thead", {}, [el("tr", {}, [el("th", {}, ["Name"]), el("th", {}, ["Status"]), el("th", {}, ["Enrolled"]), el("th", {}, ["Certificate"]), el("th", {}, [""])])]), el("tbody", {}, rows)])
      : el("p", { class: "muted" }, ["No devices yet. Create an invitation above."]),
  ]));
}

function inviteCard() {
  const name = /** @type {HTMLInputElement} */ (el("input", { placeholder: "e.g. alice-laptop", maxlength: "64", autocomplete: "off" }));
  const hours = /** @type {HTMLSelectElement} */ (el("select", {}, [
    el("option", { value: "1" }, ["1 hour"]), el("option", { value: "24", selected: "" }, ["24 hours"]), el("option", { value: "72" }, ["3 days"]),
  ]));
  const create = button("Create invitation");
  const out = el("div");
  busy(create, async () => {
    const n = name.value.trim();
    if (!/^[A-Za-z0-9._-]{1,64}$/.test(n)) throw new Error("Use 1–64 letters, digits, dots, dashes or underscores for the device name.");
    const { data } = await api("POST", "/devices/invite", { body: { name: n, expires_in_hours: Number(hours.value) } });
    const code = /** @type {HTMLTextAreaElement} */ (el("textarea", { class: "code", readonly: "", rows: "4", "aria-label": "Invitation code" }));
    code.value = data.code;
    const copyBtn = button("Copy code");
    copyBtn.addEventListener("click", () => copy(data.code));
    const dl = button("Download .aegis file", "ghost");
    dl.addEventListener("click", () => download(n + ".aegis", data.code + "\n"));
    const done = button("Done", "ghost");
    done.addEventListener("click", () => { out.replaceChildren(); name.value = ""; });
    out.replaceChildren(el("div", { class: "secret" }, [
      el("p", {}, [el("strong", {}, ["Invitation for " + data.name]), " — valid once, until " + when(data.expires_at) + "."]),
      code,
      el("div", { class: "row" }, [copyBtn, dl, done]),
      el("ol", { class: "steps" }, [
        el("li", {}, ["Install and open the AegisNet client app on the device (downloads below)."]),
        el("li", {}, ["Choose ", el("em", {}, ["Add server"]), " and paste this code (or open the .aegis file)."]),
        el("li", {}, ["Click ", el("em", {}, ["Connect"]), ". The device creates its own key; the code cannot be reused."]),
      ]),
      el("p", { class: "muted small" }, ["Devices will connect to " + data.url + "."]),
    ]));
    code.select();
  });
  return card("Invite a device", [
    el("p", { class: "muted" }, ["An invitation lets one device join. Share it only with the device's owner."]),
    el("div", { class: "cols" }, [field("Device name", name), field("Valid for", hours)]),
    el("div", { class: "row" }, [create]),
    out,
  ]);
}

async function downloadsCard() {
  try {
    const { data } = await api("GET", "/system/downloads");
    if (!data.items.length) return el("span");
    return card("Client apps", [
      el("p", { class: "muted" }, ["Portable apps — no installation needed. Run, paste an invitation, connect."]),
      el("ul", { class: "downloads" }, data.items.map((/** @type {any} */ f) =>
        el("li", {}, [el("a", { href: BASE + "/downloads/" + encodeURIComponent(f.name), download: f.name }, [f.label || f.name]), el("span", { class: "muted small" }, [" " + fmtBytes(f.size) + (f.sha256 ? " · SHA-256 " + f.sha256.slice(0, 16) + "…" : "")])]))),
    ]);
  } catch {
    return el("span");
  }
}

// ---------------------------------------------------------------- users

async function renderUsers() {
  const v = root();
  const username = /** @type {HTMLInputElement} */ (el("input", { autocomplete: "off", placeholder: "e.g. alice" }));
  const role = /** @type {HTMLSelectElement} */ (el("select", {}, [
    el("option", { value: "user" }, ["User — manages own devices"]),
    el("option", { value: "viewer" }, ["Viewer — read-only console"]),
    el("option", { value: "operator" }, ["Operator — configuration"]),
    el("option", { value: "owner" }, ["Owner — full control"]),
  ]));
  const create = button("Create user");
  const out = el("div");
  busy(create, async () => {
    const u = username.value.trim();
    if (!u) throw new Error("Enter a username.");
    const { data } = await api("POST", "/users", { body: { username: u, roles: [role.value] } });
    out.replaceChildren(tempPassword(u, data.temporary_password));
    username.value = "";
    await listUsers(list);
  });
  const list = el("div");
  try {
    const { data: info } = await api("GET", "/system/info");
    const pr = info.portal || {};
    portalUrl = pr.enabled && pr.url ? pr.url : null;
    const link = pr.url ? el("code", {}, [pr.url]) : el("span", { class: "muted" }, ["(available once devices have an address: see Connectivity)"]);
    const copyUrl = button("Copy address", "ghost small");
    copyUrl.hidden = !pr.url;
    copyUrl.addEventListener("click", () => copy(pr.url));
    const toggle = button(pr.enabled ? "Turn the portal off" : "Turn the portal on", pr.enabled ? "ghost small" : "small");
    toggle.hidden = !can("system:configure");
    busy(toggle, async () => { await api("PUT", "/system/portal", { body: { enabled: !pr.enabled } }); await renderUsers(); });
    const port = /** @type {HTMLInputElement} */ (el("input", { type: "number", min: "1", max: "65535", placeholder: "same as devices", value: pr.public_port ? String(pr.public_port) : "" }));
    const savePort = button("Save port", "ghost small");
    busy(savePort, async () => {
      const value = port.value.trim();
      await api("PUT", "/system/portal", { body: { public_port: value ? Number(value) : null } });
      notice(value ? "Portal address now uses port " + value + "." : "Portal address uses the device port again.");
      await renderUsers();
    });
    const portRow = el("div", {}, [
      field("Public port in the portal address (optional)", port, "Only the address users see changes: the portal is still served by the device listener. Use this when port forwarding or your firewall maps another port to it, or with Cloudflare Tunnel to use one of Cloudflare's other HTTPS ports (2053, 2083, 2087, 2096, 8443). Leave empty for the device port (443 with Cloudflare)."),
      el("div", { class: "row" }, [savePort]),
    ]);
    portRow.hidden = !can("system:configure");
    v.append(card("User portal", [
      el("p", { class: "muted" }, ["Users sign in here to add and remove their own devices and download the app, without access to this console. It is served on the same public address as devices (through Cloudflare Tunnel when set up). Administrators can sign in there too, with two-factor authentication (Account), and then get this whole console without SSH."]),
      el("p", {}, [pill(pr.enabled ? "on" : "off"), " ", link]),
      pr.warning ? el("p", { class: "warn-text" }, [pr.warning]) : null,
      el("div", { class: "row" }, [copyUrl, toggle]),
      portRow,
    ]));
  } catch { /* not an appliance */ }
  v.append(card("Add a user", [
    el("p", { class: "muted" }, ["New users get a one-time password and must choose their own at first sign-in. Users can invite and revoke only their own devices."]),
    el("div", { class: "cols" }, [field("Username", username), field("Role", role)]),
    el("div", { class: "row" }, [create]),
    out,
  ]), list);
  await listUsers(list);
}

/** @param {string} user @param {string} pw */
function tempPassword(user, pw) {
  const copyBtn = button("Copy password");
  copyBtn.addEventListener("click", () => copy(pw));
  const done = button("Done", "ghost");
  const box = el("div", { class: "secret" }, [
    el("p", {}, ["One-time password for ", el("strong", {}, [user]), ". Give it to them privately; it is shown only now."]),
    el("code", { class: "big" }, [pw]),
    el("p", { class: "muted small" }, [portalUrl ? "They sign in at " + portalUrl : "Console address: " + location.origin]),
    el("div", { class: "row" }, [copyBtn, done]),
  ]);
  done.addEventListener("click", () => box.remove());
  return box;
}

/** @param {HTMLElement} host */
async function listUsers(host) {
  const { data } = await api("GET", "/users");
  const rows = data.items.map((/** @type {any} */ u) => {
    const reset = button("Reset password", "ghost small");
    busy(reset, async () => {
      if (!confirm("Reset the password of " + u.username + "? Their sessions end immediately.")) return;
      const { data: r } = await api("POST", "/users/" + u.id + "/reset-password");
      host.prepend(tempPassword(u.username, r.temporary_password));
    });
    const toggle = button(u.status === "active" ? "Disable" : "Enable", u.status === "active" ? "danger small" : "small");
    toggle.disabled = u.id === session.principal;
    busy(toggle, async () => {
      await api("PATCH", "/users/" + u.id, { body: { status: u.status === "active" ? "disabled" : "active" } });
      await listUsers(host);
    });
    const roleSel = /** @type {HTMLSelectElement} */ (el("select", { class: "inline", "aria-label": "Role of " + u.username }, ["user", "viewer", "operator", "owner"].map((r) =>
      el("option", { value: r }, [r]))));
    roleSel.value = u.roles[0] || "user";
    roleSel.addEventListener("change", async () => {
      try {
        await api("PATCH", "/users/" + u.id, { body: { roles: [roleSel.value] } });
        notice("Role updated.");
      } catch (e) { notice(msg(e), true); roleSel.value = u.roles[0]; }
    });
    const reset2fa = u.two_factor ? button("Reset 2FA", "ghost small") : null;
    if (reset2fa) {
      busy(reset2fa, async () => {
        if (!confirm("Turn off two-factor authentication for " + u.username + "? Use this when they lost their authenticator; they can set it up again. Their sessions end.")) return;
        await api("POST", "/users/" + u.id + "/reset-2fa");
        await listUsers(host);
      });
    }
    return el("tr", {}, [
      el("td", {}, [el("strong", {}, [u.username]), u.id === session.principal ? el("span", { class: "muted" }, [" (you)"]) : null]),
      el("td", {}, [roleSel]),
      el("td", {}, [pill(u.password_change_required ? "must change password" : u.status), u.two_factor ? " " : "", u.two_factor ? pill("2FA") : null]),
      el("td", {}, [when(u.created_at)]),
      el("td", { class: "actions" }, [reset, reset2fa, toggle]),
    ]);
  });
  host.replaceChildren(card("Users", [el("table", {}, [
    el("thead", {}, [el("tr", {}, [el("th", {}, ["Username"]), el("th", {}, ["Role"]), el("th", {}, ["Status"]), el("th", {}, ["Created"]), el("th", {}, [""])])]),
    el("tbody", {}, rows),
  ])]));
}

// ---------------------------------------------------------------- connectivity

async function integrationState() {
  const { data } = await api("GET", "/integrations");
  /** @type {Record<string, any>} */
  const byId = {};
  for (const i of data.integrations || []) byId[i.id] = i;
  return { list: data.integrations || [], byId };
}

async function renderConnectivity() {
  const v = root();
  const [{ data: info }, ints] = await Promise.all([api("GET", "/system/info"), integrationState()]);
  const conn = info.connection || {};
  const cf = ints.byId.cloudflare || { state: "inactive" };
  const acme = ints.byId.acme || { state: "inactive" };
  const managed = conn.mode && conn.mode !== "direct";
  v.append(card("How devices connect", [
    el("p", {}, [
      conn.public_host
        ? el("span", {}, ["Devices connect to ", el("strong", { class: "mono" }, [conn.public_host + (conn.public_port && conn.public_port !== 443 ? ":" + conn.public_port : "")]),
          " (" + ({ direct: "direct connection, private certificate", cloudflare: "through Cloudflare Tunnel", acme: "direct, Let's Encrypt certificate" }[/** @type {"direct"} */ (conn.mode)] || conn.mode) + ")."])
        : el("span", { class: "warn-text" }, [info.tunnel_only
          ? "Not set yet. This gateway was installed with --tunnel-only, so devices can only use Cloudflare Tunnel: set it up below before inviting devices."
          : "Not set yet — choose one of the options below before inviting devices."]),
    ]),
    el("p", { class: "muted" }, ["Device traffic is always protected by mutual TLS between the device and this gateway, whichever path it takes."]),
  ]));
  if (info.tunnel_only) {
    // No public device port: direct connections and HTTP-validated
    // certificates can't work, so only the tunnel is offered.
    v.append(cloudflareCard(cf, conn));
    v.append(card("Direct connections are off", [el("p", { class: "muted" }, ["This gateway was installed with --tunnel-only: nothing on the server is reachable from the internet, and devices connect through Cloudflare Tunnel. To accept direct connections, reinstall with --direct."])]));
  } else {
    v.append(directCard(conn, managed));
    v.append(cloudflareCard(cf, conn));
    v.append(acmeCard(acme, conn));
  }
  v.append(quicCard(info.quic || {}, conn));
  if (["applying", "removing", "issuing", "planning", "verifying"].includes(cf.state) || ["issuing", "removing"].includes(acme.state)) {
    pollTimer = window.setTimeout(() => { if (currentView === "connectivity") renderConnectivity().catch(() => {}); }, 2500);
  }
}

/** @param {any} conn @param {boolean} managed */
function directCard(conn, managed) {
  const guess = conn.public_host || location.hostname;
  const host = /** @type {HTMLInputElement} */ (el("input", { value: guess, autocomplete: "off" }));
  const port = /** @type {HTMLInputElement} */ (el("input", { type: "number", min: "1", max: "65535", value: String(conn.public_port || 443) }));
  const save = button("Use this address");
  save.disabled = managed;
  busy(save, async () => {
    await api("PUT", "/system/connection", { body: { public_host: host.value.trim(), public_port: Number(port.value) } });
    notice("Saved. New invitations use " + host.value.trim() + ".");
    await renderConnectivity();
  });
  return card("Option 1 — Direct (LAN or port forwarding)", [
    el("p", { class: "muted" }, ["Simplest. Devices connect straight to this server. On a home network this works immediately on the LAN; for access from outside, forward a TCP port on your router to this server's edge port (default host port 443)."]),
    managed ? el("p", { class: "warn-text" }, ["An integration currently manages the address. Disable it to switch back."]) : null,
    el("div", { class: "cols" }, [
      field("Server address (IP or DNS name)", host, "The address devices use. Detected from your browser: " + location.hostname),
      field("Port", port, "The host port forwarded to the gateway's edge listener."),
    ]),
    el("div", { class: "row" }, [save]),
  ]);
}

/** Direct QUIC: a faster UDP path next to the usual address.
 * @param {any} q @param {any} conn */
function quicCard(q, conn) {
  const viaCloudflare = conn.mode === "cloudflare";
  const host = /** @type {HTMLInputElement} */ (el("input", { autocomplete: "off", value: q.host || "", placeholder: viaCloudflare ? "the server's public IP or DNS name" : "same as devices: " + (conn.public_host || "") }));
  const port = /** @type {HTMLInputElement} */ (el("input", { type: "number", min: "1", max: "65535", value: q.port ? String(q.port) : "", placeholder: viaCloudflare ? "the UDP port forwarded here" : "same as devices: " + String(conn.public_port || 443) }));
  const toggle = button(q.enabled ? "Turn QUIC off" : "Turn QUIC on", q.enabled ? "ghost small" : "small");
  busy(toggle, async () => {
    await api("PUT", "/system/quic", { body: { enabled: !q.enabled } });
    await renderConnectivity();
  });
  const save = button("Save QUIC address", "ghost small");
  busy(save, async () => {
    const h = host.value.trim();
    const p = port.value.trim();
    await api("PUT", "/system/quic", { body: { host: h || null, port: p ? Number(p) : null } });
    notice("Saved. Devices use it from their next connection.");
    await renderConnectivity();
  });
  const controls = el("div", {}, [
    el("div", { class: "cols" }, [
      field("Server address for QUIC (optional)", host, viaCloudflare
        ? "Required with Cloudflare Tunnel: Cloudflare can't carry QUIC, so devices need this server's own address. Using it shows that address to every device."
        : "Leave empty to use the device address."),
      field("UDP port (optional)", port, "Leave empty for the device port number. Forward this UDP port on your router or firewall to the server."),
    ]),
    el("div", { class: "row" }, [save, toggle]),
  ]);
  controls.hidden = !can("system:configure");
  return card("Direct QUIC (faster UDP, for games and calls)", [
    el("p", { class: "muted" }, ["Devices try QUIC over UDP first and use the usual address when it can't connect. With QUIC, app UDP (games, calls, QUIC websites) travels as UDP the whole way instead of inside a TCP connection, so a lost packet no longer stalls everything behind it. Same certificates and policy as the usual path."]),
    el("p", { class: "muted" }, ["The server must be reachable on a UDP port: install or upgrade with ", el("code", {}, ["sudo sh install.sh --quic"]), " to publish it (the device port number, over UDP), and forward that UDP port on your router if needed."]),
    el("p", {}, [pill(q.enabled ? "on" : "off"), " ", q.address ? el("code", {}, [q.address]) : el("span", { class: "muted" }, [q.enabled ? "(no address yet)" : ""])]),
    q.warning ? el("p", { class: "warn-text" }, [q.warning]) : null,
    controls,
  ]);
}

/** The port devices use through the tunnel: one of Cloudflare's HTTPS ports.
 * @param {any} conn */
function tunnelPort(conn) {
  const port = /** @type {HTMLSelectElement} */ (el("select", {}, [443, 2053, 2083, 2087, 2096, 8443].map((p) =>
    el("option", { value: String(p) }, [String(p) + (p === 443 ? " (standard HTTPS)" : "")]))));
  port.value = String(conn.public_port || 443);
  const save = button("Use this port", "ghost small");
  busy(save, async () => {
    await api("PUT", "/system/connection", { body: { public_port: Number(port.value) } });
    notice("New invitations use port " + port.value + ". Joined devices switch to it the next time they connect.");
    await renderConnectivity();
  });
  return el("div", {}, [
    field("Device port", port, "Cloudflare accepts HTTPS on these ports and passes all of them through the tunnel; pick another if a network blocks 443. Joined devices move over by themselves; the old port keeps working."),
    el("div", { class: "row" }, [save]),
  ]);
}

/** Connector updates: the last check, automatic updates, "Update now".
 * @param {any} conn */
function connectorUpdates(conn) {
  const u = conn.update || {};
  const when = u.checked_at ? new Date(u.checked_at * 1000).toLocaleString() : null;
  const last = u.error ? el("p", { class: "err-text" }, ["Last update check" + (when ? " (" + when + ")" : "") + " failed: " + u.error])
    : u.updated ? el("p", { class: "muted" }, ["Updated to cloudflared " + u.version + (when ? " on " + when : "") + "."])
    : when ? el("p", { class: "muted" }, ["Up to date (latest is " + (u.latest || u.version) + ", checked " + when + ")."])
    : null;
  const auto = /** @type {HTMLInputElement} */ (el("input", { type: "checkbox" }));
  auto.checked = conn.auto_update !== false;
  auto.addEventListener("change", async () => {
    try {
      await api("POST", "/integrations/cloudflare/connector-auto-update", { body: { enabled: auto.checked } });
      notice(auto.checked ? "Automatic connector updates are on." : "Automatic connector updates are off.");
    } catch (e) {
      auto.checked = !auto.checked;
      notice(String(e), true);
    }
  });
  const now = button(conn.updating ? "Updating…" : "Update now", "ghost");
  /** @type {HTMLButtonElement} */ (now).disabled = !!conn.updating;
  busy(now, async () => {
    const r = await api("POST", "/integrations/cloudflare/update-connector", { body: {} });
    notice(r.updated ? "Connector updated to cloudflared " + r.version + "." : "The connector is up to date (cloudflared " + r.version + ").");
    await renderConnectivity();
  });
  return el("div", {}, [
    last,
    el("label", { class: "check" }, [auto, " Keep the connector up to date (checks weekly and when the gateway starts; the tunnel reconnects within seconds)"]),
    el("div", { class: "row" }, [now]),
  ]);
}

/** @param {any} cf @param {any} conn */
function cloudflareCard(cf, conn) {
  const body = el("div");
  const head = el("div", { class: "row spread" }, [el("span", {}, ["Status: ", pill(cf.state || "inactive")]), cf.public_url ? el("span", { class: "mono" }, [cf.public_url]) : null]);
  const c = card("Option 2 — Cloudflare Tunnel (access from anywhere, no port forwarding)", [
    el("p", { class: "muted" }, ["Uses your Cloudflare account and domain. AegisNet creates the tunnel, the DNS record and runs the connector itself — no dashboard steps. Your router needs no open ports. Cloudflare sees encrypted device traffic only; device authentication stays end-to-end."]),
    head,
    cf.error ? el("p", { class: "err-text" }, ["Last error: " + cf.error]) : null,
    cf.warning ? el("p", { class: "warn-text" }, [cf.warning]) : null,
    cf.step && cf.state !== "active" ? el("p", { class: "muted" }, ["Step: " + cf.step]) : null,
    cf.connector ? el("p", { class: "muted" }, ["Connector: " + (cf.connector.ready ? "connected to Cloudflare" : cf.connector.running ? "starting…" : "stopped") + (cf.connector.version ? " (cloudflared " + cf.connector.version + ")" : "")]) : null,
    body,
  ]);
  if (cf.available === false) {
    body.append(el("p", { class: "warn-text" }, ["The Cloudflare connector is not bundled with this installation: " + (cf.unavailable_reason || "unknown reason")]));
    return c;
  }
  const token = /** @type {HTMLInputElement} */ (el("input", { type: "password", autocomplete: "off", spellcheck: "false", placeholder: "Cloudflare API token" }));
  const tokenHelp = el("details", { class: "help" }, [el("summary", {}, ["How do I create the token?"]), el("ol", {}, [
    el("li", {}, ["Cloudflare dashboard → My Profile → API Tokens → Create Token → Create Custom Token."]),
    el("li", {}, ["Permissions: Account · Cloudflare Tunnel · Edit; Zone · DNS · Edit; Zone · Zone · Read."]),
    el("li", {}, ["Account and zone resources: only the account and domain you will use."]),
    el("li", {}, ["The token is used for this setup only and is not stored unless you choose to (needed for automatic certificate renewal with DNS validation)."]),
  ])]);
  if (cf.state === "active" || cf.state === "failed" || cf.state === "recovery_required") {
    const keepDns = /** @type {HTMLInputElement} */ (el("input", { type: "checkbox" }));
    const restart = button("Restart connector", "ghost");
    busy(restart, async () => { await api("POST", "/integrations/cloudflare/restart", { body: {} }); notice("Connector restarted."); await renderConnectivity(); });
    if (cf.state === "active" && conn.mode === "cloudflare" && can("system:configure")) body.append(tunnelPort(conn));
    if (cf.state === "active" && cf.connector) body.append(connectorUpdates(cf.connector));
    const outdated = cf.state === "active" && cf.portal_routes === false;
    const retry = button(outdated ? "Update routes for the user portal" : cf.state === "active" ? "Test again" : "Retry setup", "ghost");
    retry.hidden = cf.state === "active" && !cf.warning && !outdated;
    if (outdated) {
      body.append(el("p", { class: "muted" }, ["This tunnel was set up before the user portal existed. Paste the token and press Update routes so users can reach the portal through it."]));
    }
    busy(retry, async () => {
      if (!token.value) throw new Error("Paste the API token to retry.");
      await api("POST", "/integrations/cloudflare/apply", { body: { token: token.value, plan_id: cf.plan_id } });
      token.value = "";
      await renderConnectivity();
    });
    const off = button("Disconnect Cloudflare", "danger");
    busy(off, async () => {
      if (!token.value) throw new Error("Paste the API token: removing the tunnel and DNS record needs it.");
      if (!confirm("Remove the AegisNet tunnel" + (keepDns.checked ? "" : " and its DNS record") + " from Cloudflare? Devices using " + (cf.hostname || "it") + " lose access until you choose another option.")) return;
      await api("POST", "/integrations/cloudflare/disable", { body: { token: token.value, keep_dns: keepDns.checked } });
      token.value = "";
      notice("Cloudflare removal started.");
      await renderConnectivity();
    });
    body.append(field("API token (only needed to retry or disconnect)", token), tokenHelp,
      el("label", { class: "check" }, [keepDns, " Keep the DNS record (only resources AegisNet created are ever removed)"]),
      el("div", { class: "row" }, [restart, retry, off]));
    return c;
  }
  if (["applying", "removing", "planning", "verifying"].includes(cf.state)) {
    body.append(el("p", {}, ["Working… this page refreshes automatically."]));
    return c;
  }
  // Wizard: token -> zones -> hostname -> preview -> apply.
  const check = button("Continue");
  const step2 = el("div");
  busy(check, async () => {
    if (!token.value.trim()) throw new Error("Paste a Cloudflare API token.");
    const { data } = await api("POST", "/integrations/cloudflare/zones", { body: { token: token.value.trim() } });
    if (!data.zones.length) throw new Error("The token works but sees no active domains. Check its zone permissions.");
    const zone = /** @type {HTMLSelectElement} */ (el("select", {}, data.zones.map((/** @type {any} */ z) => el("option", { value: z.id, "data-name": z.name }, [z.name + (z.status !== "active" ? " (" + z.status + ")" : "")]))));
    const sub = /** @type {HTMLInputElement} */ (el("input", { value: "aegis", autocomplete: "off" }));
    const preview = el("div");
    const show = () => {
      const opt = zone.selectedOptions[0];
      const z = opt ? opt.getAttribute("data-name") : "";
      return sub.value.trim() ? sub.value.trim().toLowerCase() + "." + z : z || "";
    };
    const hostOut = el("div", { class: "help mono" }, [show()]);
    zone.addEventListener("change", () => { hostOut.textContent = show(); });
    sub.addEventListener("input", () => { hostOut.textContent = show(); });
    const plan = button("Preview changes");
    busy(plan, async () => {
      const opt = zone.selectedOptions[0];
      const { data: p } = await api("POST", "/integrations/cloudflare/plan", { body: { token: token.value.trim(), zone_id: zone.value, account_id: opt ? opt.getAttribute("data-account") || undefined : undefined, hostname: show() } });
      const store = /** @type {HTMLInputElement} */ (el("input", { type: "checkbox" }));
      const apply = button("Create tunnel and connect");
      busy(apply, async () => {
        await api("POST", "/integrations/cloudflare/apply", { body: { token: token.value.trim(), plan_id: p.plan_id, store_token: store.checked } });
        token.value = "";
        notice("Setting up Cloudflare… this usually takes under a minute.");
        await renderConnectivity();
      });
      preview.replaceChildren(el("div", { class: "plan" }, [
        el("h3", {}, ["AegisNet will:"]),
        el("ul", {}, (p.changes || []).map((/** @type {string} */ x) => el("li", {}, [x]))),
        p.warnings && p.warnings.length ? el("ul", { class: "warn-list" }, p.warnings.map((/** @type {string} */ x) => el("li", {}, [x]))) : null,
        el("label", { class: "check" }, [store, " Remember the token on this server (only needed for DNS-validated Let's Encrypt renewals)"]),
        el("div", { class: "row" }, [apply]),
      ]));
    });
    for (const o of zone.options) {
      const z = data.zones.find((/** @type {any} */ x) => x.id === o.value);
      if (z) o.setAttribute("data-account", z.account_id);
    }
    step2.replaceChildren(
      el("div", { class: "cols" }, [field("Domain", zone), field("Subdomain", sub, "Leave empty to use the domain itself.")]),
      el("p", {}, ["Public address: "]), hostOut,
      el("div", { class: "row" }, [plan]),
      preview,
    );
  });
  body.append(field("Cloudflare API token", token), tokenHelp, el("div", { class: "row" }, [check]), step2);
  return c;
}

/** @param {any} acme @param {any} conn */
function acmeCard(acme, conn) {
  const body = el("div");
  const c = card("Option 3 — Public certificate (Let's Encrypt) for direct connections", [
    el("p", { class: "muted" }, ["Optional, for a public DNS name pointing at this server (with port forwarding). Devices then trust the edge with standard public certificates; renewal is automatic."]),
    el("div", { class: "row spread" }, [el("span", {}, ["Status: ", pill(acme.state || "inactive")]), acme.hostname ? el("span", { class: "mono" }, [acme.hostname]) : null]),
    acme.expires_at ? el("p", { class: "muted" }, ["Certificate valid until " + when(acme.expires_at) + (acme.staging ? " (staging — not publicly trusted)" : "")]) : null,
    acme.error ? el("p", { class: "err-text" }, ["Last error: " + acme.error]) : null,
    body,
  ]);
  if (acme.state === "active") {
    const renew = button("Renew now", "ghost");
    busy(renew, async () => { await api("POST", "/integrations/acme/renew", { body: {} }); notice("Renewal started."); await renderConnectivity(); });
    const off = button("Stop using the public certificate", "danger");
    busy(off, async () => {
      if (!confirm("Switch the edge back to the private certificate? Existing devices need a new invitation afterwards.")) return;
      await api("POST", "/integrations/acme/disable", { body: {} });
      await renderConnectivity();
    });
    body.append(el("div", { class: "row" }, [renew, off]));
    return c;
  }
  if (acme.state === "issuing") { body.append(el("p", {}, ["Requesting a certificate… this page refreshes automatically."])); return c; }
  const host = /** @type {HTMLInputElement} */ (el("input", { placeholder: "vpn.example.com", autocomplete: "off", value: conn.mode === "direct" && conn.public_host && !/^[0-9.:]+$/.test(conn.public_host) ? conn.public_host : "" }));
  const email = /** @type {HTMLInputElement} */ (el("input", { type: "email", placeholder: "you@example.com", autocomplete: "email" }));
  const port = /** @type {HTMLInputElement} */ (el("input", { type: "number", min: "1", max: "65535", value: String(conn.public_port || 443) }));
  const challenge = /** @type {HTMLSelectElement} */ (el("select", {}, [
    el("option", { value: "http-01" }, ["HTTP validation — port 80 forwarded to the server's HTTP port"]),
    el("option", { value: "dns-01-cloudflare" }, ["DNS validation via Cloudflare API (no open port 80)"]),
  ]));
  const token = /** @type {HTMLInputElement} */ (el("input", { type: "password", autocomplete: "off", placeholder: "Cloudflare API token (DNS · Edit)" }));
  const tokenField = field("Cloudflare API token", token, "Stored on this server so renewals can run automatically.");
  tokenField.hidden = true;
  challenge.addEventListener("change", () => { tokenField.hidden = challenge.value !== "dns-01-cloudflare"; });
  const staging = /** @type {HTMLInputElement} */ (el("input", { type: "checkbox" }));
  const terms = /** @type {HTMLInputElement} */ (el("input", { type: "checkbox" }));
  const issue = button("Get certificate");
  busy(issue, async () => {
    if (!terms.checked) throw new Error("Accept the Let's Encrypt Subscriber Agreement to continue.");
    await api("POST", "/integrations/acme/issue", { body: {
      hostname: host.value.trim().toLowerCase(), email: email.value.trim(), challenge: challenge.value,
      token: challenge.value === "dns-01-cloudflare" ? token.value.trim() : undefined,
      staging: staging.checked, terms_accepted: true, public_port: Number(port.value),
    } });
    token.value = "";
    notice("Requesting the certificate…");
    await renderConnectivity();
  });
  body.append(
    el("div", { class: "cols" }, [field("Public DNS name", host), field("Contact email", email, "Let's Encrypt sends expiry warnings here.")]),
    el("div", { class: "cols" }, [field("Validation", challenge), field("Public port devices use", port)]),
    tokenField,
    el("label", { class: "check" }, [staging, " Use the staging environment (testing; not publicly trusted)"]),
    el("label", { class: "check" }, [terms, " I accept the ", el("a", { href: "https://letsencrypt.org/repository/", target: "_blank", rel: "noopener noreferrer" }, ["Let's Encrypt Subscriber Agreement"])]),
    el("div", { class: "row" }, [issue]),
  );
  return c;
}

// ---------------------------------------------------------------- integrations

async function renderIntegrations() {
  const v = root();
  const { data } = await api("GET", "/integrations");
  v.append(card("Integrations", [
    el("p", { class: "muted" }, [data.third_party_plugins || ""]),
  ]));
  if (!data.appliance) {
    v.append(card("", [el("p", { class: "muted" }, ["Integrations are managed by the appliance runtime, which this node is not running (hand-configured node). Use the CLI provisioning workflow instead."])]));
    return;
  }
  for (const i of data.integrations) {
    const go = i.id === "cloudflare" || i.id === "acme" ? button("Configure", "small") : null;
    if (go) go.addEventListener("click", () => view("connectivity"));
    v.append(el("section", { class: "card integration" }, [
      el("div", { class: "row spread" }, [el("h2", {}, [i.name]), pill(i.state || (i.enabled ? "enabled" : "inactive"))]),
      el("p", { class: "muted" }, [i.description || ""]),
      i.error ? el("p", { class: "err-text" }, [i.error]) : null,
      go ? el("div", { class: "row" }, [go]) : null,
    ]));
  }
}

// ---------------------------------------------------------------- configuration (advanced)

async function renderConfiguration() {
  const v = root();
  const { data } = await api("GET", "/profiles?limit=100");
  v.append(card("Advanced configuration", [
    el("p", { class: "muted" }, ["Routing, DNS and egress policy as versioned JSON. Saving creates an immutable revision; nothing changes until it is validated and activated. Secrets are secret:// references only."]),
  ]));
  if (!data.items.length) { v.append(card("", ["No profiles."])); return; }
  const select = /** @type {HTMLSelectElement} */ (el("select", { "aria-label": "Profile" }, data.items.map((/** @type {any} */ p) =>
    el("option", { value: p.id }, [p.name + (p.active_revision_id ? " (active " + p.active_revision_id.slice(0, 8) + ")" : "")]))));
  v.append(card("", [field("Profile", select)]));
  const editor = el("div");
  v.append(editor);
  const load = () => renderProfile(select.value, editor).catch((e) => notice(msg(e), true));
  select.addEventListener("change", load);
  await load();
}

/** @param {string} id @param {HTMLElement} host */
async function renderProfile(id, host) {
  const { data: p, etag } = await api("GET", "/profiles/" + id);
  const text = /** @type {HTMLTextAreaElement} */ (el("textarea", { spellcheck: "false", "aria-label": "Specification (JSON)", class: "editor" }));
  text.value = JSON.stringify(p.specification, null, 2);
  const report = el("div");
  const save = button("Save as new revision", "ghost");
  save.disabled = !can("profiles:write");
  const validate = button("Validate");
  host.replaceChildren(card(p.name, [
    el("p", { class: "muted mono small" }, ["desired " + p.desired_revision_id + " · active " + (p.active_revision_id || "none")]),
    text,
    el("div", { class: "row" }, [save, validate]),
    report,
  ]));
  busy(save, async () => {
    const spec = JSON.parse(text.value);
    await api("PATCH", "/profiles/" + id, { body: { specification: spec }, contentType: "application/merge-patch+json", headers: { "If-Match": etag || "" } });
    notice("Saved a new desired revision. Validate and activate it to apply.");
    await renderProfile(id, host);
  });
  busy(validate, async () => {
    const { data: r } = await api("POST", "/profiles/" + id + "/validate", { body: { target_revision_id: p.desired_revision_id }, headers: { "If-Match": etag || "" } });
    showReport(r, id, etag || "", report, host);
  });
}

/** @param {any} r @param {string} id @param {string} etag @param {HTMLElement} out @param {HTMLElement} host */
function showReport(r, id, etag, out, host) {
  /** @param {string} title @param {string[]} items */
  const list = (title, items) => items.length ? el("div", {}, [el("strong", {}, [title]), el("ul", { class: "plain" }, items.map((x) => el("li", {}, [x])))]) : null;
  const activate = button("Activate this revision");
  activate.disabled = !r.valid || !can("profiles:activate");
  out.replaceChildren(el("div", { class: r.valid ? "report ok" : "report bad" }, [
    el("h3", {}, [r.valid ? "Validation passed" : "Validation failed"]),
    list("Errors", r.errors), list("Warnings", r.warnings), list("Security-relevant changes", r.security_diff),
    el("div", { class: "row" }, [activate]),
  ]));
  busy(activate, async () => {
    const { data: job } = await api("POST", "/profiles/" + id + "/activate", {
      body: { target_revision_id: r.target_revision_id, config_digest: r.config_digest, validation_id: r.validation_id },
      headers: { "If-Match": etag, "Idempotency-Key": randomKey() },
    });
    await pollJob(job.id);
    await renderProfile(id, host);
  });
}

/** @param {string} jobId */
async function pollJob(jobId) {
  for (let i = 0; i < 60; i++) {
    const { data: j } = await api("GET", "/jobs/" + jobId);
    if (j.status === "succeeded") { notice("Activated."); return; }
    if (j.status === "failed" || j.status === "cancelled") { notice("Activation " + j.status + " (" + (j.safe_error_code || "no code") + "); the running policy is unchanged.", true); return; }
    if (j.status === "reconciling") { notice("Committed but still reconciling; new connections are held. See `aegisctl activation inspect`.", true); return; }
    await new Promise((res) => setTimeout(res, 500));
  }
  notice("Still running; check again later.", true);
}

// ---------------------------------------------------------------- diagnostics

/** @param {number} seconds */
function mins(seconds) {
  const m = Math.floor(seconds / 60), s = seconds % 60;
  return m ? `${m} min ${s} s` : `${s} s`;
}

/** @param {number|null|undefined} unix */
function at(unix) {
  return unix ? new Date(unix * 1000).toLocaleTimeString() : "—";
}

async function renderDiagnostics() {
  const v = root();
  const { data } = await api("GET", "/diagnostics");
  const g = data.gateway;
  const lim = data.limits;
  const status = g.state === "recording"
    ? `Recording · ${mins(g.remaining_seconds || 0)} left · ${g.events} events`
    : g.state === "stopped"
      ? `Stopped at ${at(g.ends_unix)} · ${g.events} events · kept until ${at(g.discard_unix)}`
      : "Off";

  const controls = el("div", { class: "row" }, []);
  if (g.state === "recording") {
    const stop = button("Stop recording");
    busy(stop, async () => { await api("POST", "/diagnostics/stop"); await renderDiagnostics(); });
    controls.append(stop);
  } else {
    const minutes = /** @type {HTMLSelectElement} */ (el("select", { class: "inline", "aria-label": "Duration" },
      [5, 15, 30, 60].filter((m) => m <= lim.max_minutes).map((m) => el("option", { value: String(m) }, [`${m} minutes`]))));
    minutes.value = "15";
    const start = button(g.state === "stopped" ? "Start a new recording" : "Start recording");
    busy(start, async () => {
      await api("POST", "/diagnostics/start", { body: { minutes: Number(minutes.value) } });
      notice("Recording. Now start recording on the device too and reproduce the problem.");
      await renderDiagnostics();
    });
    controls.append(el("span", {}, ["Record for"]), minutes, start);
  }
  if (g.state !== "off" || data.devices.length) {
    const discard = button("Discard everything", "ghost");
    busy(discard, async () => { await api("POST", "/diagnostics/discard"); notice("Diagnostics discarded."); await renderDiagnostics(); });
    controls.append(discard);
  }

  v.append(card("Diagnostics", [
    el("p", { class: "muted" }, [
      `When something doesn't work, record what the gateway and the device see while you reproduce it, then read the analysis below. Off by default. A recording stops by itself after at most ${lim.max_minutes} minutes, is held in memory only (at most ${Math.round(lim.max_bytes / 1048576)} MB per recording, oldest events deleted first) and is dropped ${lim.retain_minutes} minutes after it ends. It holds connection events and error messages, never visited sites or traffic.`,
    ]),
    el("div", { class: "row" }, [el("strong", {}, ["Gateway: "]), pill(g.state === "recording" ? "running" : g.state === "stopped" ? "stopped" : "off"), el("span", { class: "muted" }, [status])]),
    controls,
    el("h3", {}, ["How to diagnose a device"]),
    el("ol", { class: "steps" }, [
      el("li", {}, ["Start recording here."]),
      el("li", {}, ["On the device, open the AegisNet app → Troubleshooting → Start recording."]),
      el("li", {}, ["Reproduce the problem, then press Stop and send in the app (it also sends by itself when its recording ends)."]),
      el("li", {}, ["Read the analysis below. A device that can't reach this server can Save to file instead; import that file here."]),
    ]),
  ]));

  // Device reports.
  const rows = data.devices.map((/** @type {any} */ d) => el("tr", {}, [
    el("td", {}, [d.name]), el("td", {}, [at(d.started_unix) + " – " + at(d.ended_unix)]),
    el("td", {}, [String(d.events) + (d.dropped ? ` (+${d.dropped} older deleted)` : "")]), el("td", { class: "muted" }, [at(d.received_unix)]),
  ]));
  const file = /** @type {HTMLInputElement} */ (el("input", { type: "file", accept: ".json,.gz,application/json", "aria-label": "Report file" }));
  const importBtn = button("Import report file", "ghost small");
  busy(importBtn, async () => {
    const f = file.files && file.files[0];
    if (!f) throw new Error("Choose the report file the device saved first.");
    /** @type {Record<string,string>} */
    const headers = { "Content-Type": "application/octet-stream", Accept: "application/json" };
    if (session.csrf) headers["X-CSRF-Token"] = session.csrf;
    const resp = await fetch(BASE + "/api/v1/diagnostics/devices", { method: "POST", headers, body: await f.arrayBuffer(), credentials: "same-origin" });
    if (!resp.ok) {
      const e = await resp.json().catch(() => ({}));
      throw new Error(e.detail || friendly(e.aegis_error_code || String(resp.status)));
    }
    notice("Report imported.");
    await renderDiagnostics();
  });
  v.append(card("Device reports", [
    data.devices.length
      ? el("table", {}, [el("thead", {}, [el("tr", {}, [el("th", {}, ["Device"]), el("th", {}, ["Recorded"]), el("th", {}, ["Events"]), el("th", {}, ["Received"])])]), el("tbody", {}, rows)])
      : el("p", { class: "muted" }, [g.state === "off" ? "Devices can send reports while diagnostics are on." : "No device has sent a report yet."]),
    el("div", { class: "row" }, [file, importBtn]),
  ]));

  // Analysis.
  if (g.state !== "off" || data.devices.length) {
    const { data: a } = await api("GET", "/diagnostics/analysis");
    const items = a.findings.map((/** @type {any} */ f) => {
      const cls = f.severity === "error" ? "bad" : f.severity === "warn" ? "warn" : "ok";
      return el("div", { class: "report " + (cls === "bad" ? "bad" : cls === "ok" ? "ok" : "") }, [
        el("div", { class: "row spread" }, [el("strong", {}, [f.title]), el("span", { class: "pill " + cls }, [f.severity])]),
        f.detail ? el("p", {}, [f.detail]) : null,
        el("p", {}, [el("strong", {}, ["What to do: "]), f.action]),
        f.evidence.length ? el("p", { class: "muted small mono" }, [f.evidence.join(" · ")]) : null,
      ]);
    });
    const exp = button("Download as OpenTelemetry logs (OTLP/JSON)", "ghost small");
    busy(exp, async () => {
      const resp = await fetch(BASE + "/api/v1/diagnostics/otlp", { credentials: "same-origin" });
      if (!resp.ok) throw new Error("Nothing to download yet.");
      download("aegisnet-diagnostics.otlp.json", await resp.text(), "application/json");
    });
    v.append(card("Analysis", [...items, el("div", { class: "row" }, [exp])]));
  }

  // Refresh while recording so arriving device reports and the analysis show up.
  if (g.state === "recording") {
    pollTimer = window.setTimeout(() => { if (currentView === "diagnostics") renderDiagnostics().catch(() => {}); }, 5000);
  }
}

// ---------------------------------------------------------------- audit

async function renderAudit() {
  const v = root();
  const { data } = await api("GET", "/audit?limit=100");
  const rows = data.items.map((/** @type {any} */ a) =>
    el("tr", {}, [el("td", {}, [when(a.timestamp)]), el("td", {}, [a.action]), el("td", {}, [pill(a.decision)]), el("td", { class: "mono small" }, [a.target_type + (a.target_id ? " " + a.target_id.slice(0, 8) : "")])]));
  v.append(card("Audit log (append-only, no secrets)", [
    el("table", {}, [el("thead", {}, [el("tr", {}, [el("th", {}, ["Time"]), el("th", {}, ["Action"]), el("th", {}, ["Decision"]), el("th", {}, ["Target"])])]), el("tbody", {}, rows)]),
  ]));
}

// ---------------------------------------------------------------- account

async function renderAccount() {
  const v = root();
  const f = passwordForm(false);
  f.form.classList.remove("narrow");
  v.append(card("Signed in", [el("p", {}, [el("strong", {}, [session.username]), " · " + session.roles.join(", ")])]), f.form);
  try { v.append(await twoFactorCard()); } catch { /* older gateway */ }
  if (can("system:configure")) {
    const dl = button("Download web CA certificate", "ghost");
    busy(dl, async () => {
      const resp = await fetch(BASE + "/api/v1/system/web-ca.pem", { credentials: "same-origin" });
      if (!resp.ok) throw new Error("Download failed.");
      download("aegisnet-web-ca.pem", await resp.text(), "application/x-pem-file");
    });
    v.append(card("Trust this console in your browser (optional)", [
      el("p", { class: "muted" }, ["The console uses a certificate from this server's own web CA, so browsers warn the first time. To remove the warning, install this CA as trusted on your computer — only do this if you trust this server's operators."]),
      el("div", { class: "row" }, [dl]),
    ]));
    const ca = await deviceCaCard().catch(() => null);
    if (ca) v.append(ca);
  }
}

/** Draw a QR code from rows of "1"/"0" modules (no inline images under the CSP). */
function qrSvg(/** @type {string[]} */ rows) {
  const ns = "http://www.w3.org/2000/svg";
  const n = rows.length, q = 4, size = n + 2 * q;
  const svg = document.createElementNS(ns, "svg");
  svg.setAttribute("viewBox", "0 0 " + size + " " + size);
  svg.setAttribute("width", "200"); svg.setAttribute("height", "200");
  svg.setAttribute("role", "img"); svg.setAttribute("aria-label", "QR code for your authenticator app");
  const bg = document.createElementNS(ns, "rect");
  bg.setAttribute("width", String(size)); bg.setAttribute("height", String(size)); bg.setAttribute("fill", "#fff");
  svg.append(bg);
  rows.forEach((row, y) => {
    for (let x = 0; x < row.length; x++) {
      if (row[x] !== "1") continue;
      const r = document.createElementNS(ns, "rect");
      r.setAttribute("x", String(x + q)); r.setAttribute("y", String(y + q));
      r.setAttribute("width", "1"); r.setAttribute("height", "1"); r.setAttribute("fill", "#000");
      svg.append(r);
    }
  });
  return svg;
}

/** Two-factor authentication for the signed-in account. */
async function twoFactorCard() {
  const { data } = await api("GET", "/auth/2fa");
  const admin = session.scopes.some((s) => s !== "devices:self" && s !== "self:password");
  const why = admin
    ? "Required to sign in to this console through the public address (the user portal), so you can manage the gateway without SSH. On the local console it adds a second check."
    : "Adds a second check when you sign in: a code from an authenticator app on your phone.";
  if (data.enabled) {
    const pw = /** @type {HTMLInputElement} */ (el("input", { type: "password", autocomplete: "current-password" }));
    const code = /** @type {HTMLInputElement} */ (el("input", { autocomplete: "one-time-code", inputmode: "numeric" }));
    const off = button("Turn off two-factor authentication", "danger");
    busy(off, async () => {
      await api("POST", "/auth/2fa/disable", { body: { password: pw.value, code: code.value.trim() } });
      notice("Two-factor authentication is off.");
      await renderAccount();
    });
    return card("Two-factor authentication", [
      el("p", {}, [pill("on"), " ", el("span", { class: "muted" }, [data.recovery_codes_left + " recovery codes left"])]),
      el("p", { class: "muted" }, [why]),
      el("details", {}, [el("summary", {}, ["Turn off"]), el("div", { class: "cols" }, [field("Password", pw), field("Current code", code)]), el("div", { class: "row" }, [off])]),
    ]);
  }
  const start = button("Set up two-factor authentication");
  const flow = el("div");
  busy(start, async () => {
    const { data: s } = await api("POST", "/auth/2fa/setup");
    const code = /** @type {HTMLInputElement} */ (el("input", { autocomplete: "one-time-code", inputmode: "numeric" }));
    const confirmBtn = button("Turn on");
    busy(confirmBtn, async () => {
      const { data: r } = await api("POST", "/auth/2fa/enable", { body: { code: code.value.trim() } });
      const copyCodes = button("Copy recovery codes", "ghost small");
      copyCodes.addEventListener("click", () => copy(r.recovery_codes.join("\n")));
      const done = button("I saved them");
      done.addEventListener("click", () => renderAccount());
      flow.replaceChildren(el("div", { class: "secret" }, [
        el("p", {}, [el("strong", {}, ["Two-factor authentication is on."]), " Save these recovery codes somewhere safe. Each one works once if you lose your phone; they are shown only now."]),
        el("ul", { class: "plain mono" }, r.recovery_codes.map((/** @type {string} */ c) => el("li", {}, [c]))),
        el("div", { class: "row" }, [copyCodes, done]),
      ]));
    });
    flow.replaceChildren(
      el("ol", { class: "steps" }, [
        el("li", {}, ["Open an authenticator app on your phone (for example Google Authenticator, Microsoft Authenticator, 1Password or Bitwarden) and scan this code."]),
        el("li", {}, ["Enter the 6-digit code it shows, then press Turn on."]),
      ]),
      qrSvg(s.qr),
      el("p", { class: "muted small" }, ["Can't scan? Enter this key in the app: ", el("code", {}, [s.secret])]),
      field("Code from the app", code),
      el("div", { class: "row" }, [confirmBtn]),
    );
  });
  return card("Two-factor authentication", [
    el("p", {}, [pill("off")]),
    el("p", { class: "muted" }, [why]),
    el("div", { class: "row" }, [start]),
    flow,
  ]);
}

/** Device certificate authority: root key custody and issuer renewal (owner). */
async function deviceCaCard() {
  const { data: info } = await api("GET", "/system/info");
  if (!info.appliance) return null;
  const certs = (info.runtime || {}).certificates || {};
  const onHost = !!certs.root_key_on_host;
  const days = inDays(certs.issuer_expires_at);
  /** @param {HTMLInputElement} input */
  const keyOf = async (input) => {
    const f = input.files && input.files[0];
    if (!f) throw new Error("Choose the device root key file first.");
    return (await f.text()).trim() + "\n";
  };
  /** @param {string} action @param {any} body */
  const call = (action, body) => api("POST", "/system/device-ca/" + action, { body });
  const keyFile = () => /** @type {HTMLInputElement} */ (el("input", { type: "file", accept: ".pem,.key,.txt", "aria-label": "Device root key file" }));

  const facts = el("table", { class: "kv" }, [el("tbody", {}, [
    el("tr", {}, [el("th", {}, ["Root key"]), el("td", {}, [onHost ? pill("on this server") : pill("offline")])]),
    el("tr", {}, [el("th", {}, ["Device issuer expires"]), el("td", {}, [when(certs.issuer_expires_at), " ", days == null ? "" : pill(certs.issuer_renewal_due ? "expires in " + days + " days" : "ok · " + days + " days")])]),
    el("tr", {}, [el("th", {}, ["Root fingerprint"]), el("td", { class: "mono small" }, [certs.root_fingerprint || "—"])]),
  ])]);

  if (onHost) {
    const pw = /** @type {HTMLInputElement} */ (el("input", { type: "password", autocomplete: "current-password" }));
    const dl = button("Download the root key", "ghost");
    busy(dl, async () => {
      /** @type {Record<string,string>} */
      const headers = { "Content-Type": "application/json", Accept: "application/x-pem-file" };
      if (session.csrf) headers["X-CSRF-Token"] = session.csrf;
      const resp = await fetch(BASE + "/api/v1/system/device-ca/export-root-key", { method: "POST", headers, credentials: "same-origin", body: JSON.stringify({ password: pw.value }) });
      if (!resp.ok) {
        const e = await resp.json().catch(() => ({}));
        throw new Error(e.detail || friendly(e.aegis_error_code || String(resp.status)));
      }
      download("aegisnet-device-root-key.pem", await resp.text(), "application/x-pem-file");
      pw.value = "";
      notice("Root key downloaded. Store it somewhere safe and offline, then remove it from the server below.");
    });
    const file = keyFile();
    const remove = button("Remove the key from this server", "danger");
    busy(remove, async () => {
      await call("remove-root-key", { key_pem: await keyOf(file) });
      notice("The root key is no longer on this server. Renew the device issuer yourself before it expires.");
      await renderAccount();
    });
    const renew = button("Renew the device issuer now", "ghost small");
    busy(renew, async () => { await call("renew-issuer", {}); notice("Device issuer renewed."); await renderAccount(); });
    return card("Device certificate authority (advanced)", [
      el("p", { class: "muted" }, ["Device certificates come from a one-year issuer signed by this gateway's root. The root key is on this server, so the issuer renews by itself. For stronger protection you can keep the root key offline: then even someone who breaks into this server can't create a new root, but you must renew the issuer here once a year."]),
      facts,
      el("h3", {}, ["Take the root key offline"]),
      el("ol", { class: "steps" }, [
        el("li", {}, ["Download it (your password is checked again), and store the file offline, for example on a USB stick or in a password manager."]),
        el("li", {}, ["Choose the downloaded file to prove you have it, then remove the key from this server."]),
      ]),
      field("Your password", pw),
      el("div", { class: "row" }, [dl]),
      el("div", { class: "row" }, [file, remove]),
      el("div", { class: "row" }, [renew]),
    ]);
  }

  const file = keyFile();
  const renew = button("Renew the device issuer");
  busy(renew, async () => { await call("renew-issuer", { key_pem: await keyOf(file) }); notice("Device issuer renewed. The key was not stored."); await renderAccount(); });
  const restore = button("Put the key back on this server", "ghost");
  busy(restore, async () => { await call("restore-root-key", { key_pem: await keyOf(file) }); notice("The root key is on this server again; the issuer renews by itself."); await renderAccount(); });
  return card("Device certificate authority (advanced)", [
    el("p", { class: "muted" }, ["The root key is offline, so this server can't renew the device issuer by itself. Renew it before it expires (the console warns 60 days ahead): choose the root key file and press Renew. The key is used once in memory and not stored. Devices keep working throughout."]),
    facts,
    el("div", { class: "row" }, [file]),
    el("div", { class: "row" }, [renew, restore]),
  ], certs.issuer_renewal_due ? "warn-card" : "");
}

// ---------------------------------------------------------------- wiring

document.getElementById("logout")?.addEventListener("click", async () => {
  try { await api("POST", "/auth/logout"); } catch { /* already gone */ }
  session.csrf = null; session.principal = null; session.scopes = []; session.username = "";
  showLogin("Signed out.");
});
boot();
