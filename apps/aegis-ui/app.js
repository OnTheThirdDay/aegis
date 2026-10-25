// @ts-check
// AegisNet local console. Dependency-free; served from the loopback manager
// under a strict CSP (no inline script, no remote assets). All dynamic text
// is inserted with textContent, never innerHTML.
"use strict";

/** @type {{csrf: string|null, principal: string|null, scopes: string[]}} */
const session = { csrf: null, principal: null, scopes: [] };
let currentView = "overview";

/** @param {string} tag @param {Record<string,string>} [attrs] @param {(Node|string|null|undefined)[]} [children] */
function el(tag, attrs = {}, children = []) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") e.className = v;
    else e.setAttribute(k, v);
  }
  for (const c of children) {
    if (c == null) continue;
    e.append(typeof c === "string" ? document.createTextNode(c) : c);
  }
  return e;
}

/** @param {string} msg @param {boolean} [isError] */
function notice(msg, isError = false) {
  const n = /** @type {HTMLElement} */ (document.getElementById("notice"));
  n.textContent = msg;
  n.className = isError ? "err" : "";
}

function uuidKey() {
  const b = new Uint8Array(18);
  crypto.getRandomValues(b);
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

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
  const resp = await fetch("/api/v1" + path, { method, headers, body, credentials: "same-origin", cache: "no-store" });
  const text = await resp.text();
  /** @type {any} */
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = null; }
  if (!resp.ok) {
    const code = data && data.aegis_error_code ? data.aegis_error_code : String(resp.status);
    const detail = data && data.detail ? ": " + data.detail : "";
    const err = new Error(code + detail);
    // @ts-ignore
    err.status = resp.status;
    throw err;
  }
  return { data, etag: resp.headers.get("ETag"), status: resp.status };
}

/** @param {string} id */
function view(id) {
  currentView = id;
  for (const b of document.querySelectorAll("#nav button")) {
    b.setAttribute("aria-selected", String(b.getAttribute("data-view") === id));
  }
  notice("");
  render().catch((e) => notice(String(e.message || e), true));
}

function root() {
  const v = /** @type {HTMLElement} */ (document.getElementById("view"));
  v.replaceChildren();
  return v;
}

// ---------------------------------------------------------------- auth

async function boot() {
  try {
    const { data } = await api("GET", "/auth/me");
    session.csrf = data.csrf_token;
    session.principal = data.principal_id;
    session.scopes = data.scopes;
    signedIn();
  } catch {
    showLogin();
  }
}

function signedIn() {
  /** @type {HTMLElement} */ (document.getElementById("nav")).hidden = false;
  /** @type {HTMLElement} */ (document.getElementById("logout")).hidden = false;
  view(currentView);
}

function showLogin() {
  /** @type {HTMLElement} */ (document.getElementById("nav")).hidden = true;
  /** @type {HTMLElement} */ (document.getElementById("logout")).hidden = true;
  const v = root();
  const user = el("input", { id: "u", autocomplete: "username", required: "" });
  const pass = el("input", { id: "p", type: "password", autocomplete: "current-password", required: "" });
  const form = el("form", { class: "card narrow", "aria-labelledby": "lh" }, [
    el("h2", { id: "lh" }, ["Sign in"]),
    el("label", { for: "u" }, ["Username"]), user,
    el("label", { for: "p" }, ["Password"]), pass,
    el("div", { class: "row" }, [el("button", { type: "submit" }, ["Sign in"])]),
  ]);
  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    try {
      const { data } = await api("POST", "/auth/login", {
        body: { username: /** @type {HTMLInputElement} */ (user).value, password: /** @type {HTMLInputElement} */ (pass).value },
      });
      /** @type {HTMLInputElement} */ (pass).value = "";
      session.csrf = data.csrf_token;
      session.principal = data.principal_id;
      session.scopes = data.scopes;
      signedIn();
    } catch (e) {
      notice("Sign-in failed: " + /** @type {Error} */ (e).message, true);
    }
  });
  const tok = el("input", { id: "bt", autocomplete: "off" });
  const ou = el("input", { id: "ou", autocomplete: "username" });
  const op = el("input", { id: "op", type: "password", autocomplete: "new-password", minlength: "12" });
  const claim = el("form", { class: "card narrow", "aria-labelledby": "bh" }, [
    el("h2", { id: "bh" }, ["First-time setup"]),
    el("p", { class: "muted" }, ["Create the owner with the one-time token printed by `aegisctl bootstrap-token` on this machine."]),
    el("label", { for: "bt" }, ["Bootstrap token"]), tok,
    el("label", { for: "ou" }, ["Owner username"]), ou,
    el("label", { for: "op" }, ["Owner password (12+ characters)"]), op,
    el("div", { class: "row" }, [el("button", { type: "submit", class: "ghost" }, ["Create owner"])]),
  ]);
  claim.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    try {
      await api("POST", "/bootstrap/claim", {
        body: {
          bootstrap_token: /** @type {HTMLInputElement} */ (tok).value,
          owner_username: /** @type {HTMLInputElement} */ (ou).value,
          owner_password: /** @type {HTMLInputElement} */ (op).value,
        },
      });
      /** @type {HTMLInputElement} */ (tok).value = "";
      /** @type {HTMLInputElement} */ (op).value = "";
      notice("Owner created. Sign in above.");
    } catch (e) {
      notice("Setup failed: " + /** @type {Error} */ (e).message, true);
    }
  });
  v.append(form, claim);
  /** @type {HTMLElement} */ (user).focus();
}

// ---------------------------------------------------------------- views

async function render() {
  if (currentView === "overview") return renderOverview();
  if (currentView === "profiles") return renderProfiles();
  if (currentView === "nodes") return renderNodes();
  if (currentView === "audit") return renderAudit();
}

/** @param {string} k @param {string|number|null|undefined} v */
function stat(k, v) {
  return el("div", { class: "stat" }, [el("div", { class: "v" }, [v == null ? "—" : String(v)]), el("div", { class: "k" }, [k])]);
}

async function renderOverview() {
  const v = root();
  const { data: h } = await api("GET", "/system/health");
  const badges = /** @type {HTMLElement} */ (document.getElementById("badges"));
  badges.replaceChildren(
    el("span", { class: "badge " + (h.status === "ready" ? "ok" : h.status === "degraded" ? "bad" : "warn") }, ["Health: " + h.status]),
    el("span", { class: "badge " + (h.admission_enabled ? "ok" : "bad") }, [h.admission_enabled ? "Admission open" : "Admission closed"]),
    el("span", { class: "badge" }, ["Telemetry export: per settings (default off)"]),
  );
  const health = el("div", { class: "card" }, [
    el("h2", {}, ["Connection status"]),
    el("div", { class: "grid" }, [
      stat("Agent state", h.status),
      stat("Admission", h.admission_enabled ? "enabled" : "held"),
      stat("Version", h.version),
    ]),
    el("table", {}, [
      el("tbody", {}, [
        el("tr", {}, [el("th", {}, ["Runtime revision"]), el("td", { class: "mono" }, [h.runtime_revision_id || "none"])]),
        el("tr", {}, [el("th", {}, ["Durably applied revision"]), el("td", { class: "mono" }, [h.applied_revision_id || "none"])]),
        el("tr", {}, [el("th", {}, ["Pending committed operation"]), el("td", { class: "mono" }, [h.pending_operation_id || "none"])]),
      ]),
    ]),
    h.pending_operation_id
      ? el("p", { class: "muted" }, ["A committed activation is reconciling. Use the local CLI: aegisctl activation inspect | reconcile | supersede."])
      : null,
  ]);
  v.append(health);
  if (session.scopes.includes("telemetry:read")) {
    try {
      const { data } = await api("GET", "/system/metrics");
      const m = data.metrics;
      v.append(el("div", { class: "card" }, [
        el("h2", {}, ["Local counters (in memory, not exported)"]),
        el("div", { class: "grid" }, [
          stat("Active sessions", m.gauges.sessions_active),
          stat("Active streams", m.gauges.streams_active),
          stat("Buffer reserved (bytes)", m.gauges.buffer_total),
          stat("Streams opened", m.streams_opened),
          stat("Bytes up", m.transport_bytes_up),
          stat("Bytes down", m.transport_bytes_down),
        ]),
        data.restart_required && data.restart_required.length
          ? el("p", { class: "muted" }, ["Restart required to apply: " + data.restart_required.join(", ")])
          : null,
      ]));
    } catch (e) {
      notice(String(/** @type {Error} */ (e).message), true);
    }
  }
}

async function renderProfiles() {
  const v = root();
  const { data } = await api("GET", "/profiles?limit=100");
  if (!data.items.length) {
    v.append(el("div", { class: "card" }, ["No profiles."]));
    return;
  }
  const select = el("select", { id: "pick", "aria-label": "Profile" }, data.items.map((/** @type {any} */ p) =>
    el("option", { value: p.id }, [p.name + (p.active_revision_id ? " (active rev " + p.active_revision_id.slice(0, 8) + ")" : "")])));
  v.append(el("div", { class: "card" }, [el("label", { for: "pick" }, ["Profile"]), select]));
  const editor = el("div");
  v.append(editor);
  const load = () => renderProfile(/** @type {HTMLSelectElement} */ (select).value, editor).catch((e) => notice(e.message, true));
  select.addEventListener("change", load);
  await load();
}

/** @param {string} id @param {HTMLElement} host */
async function renderProfile(id, host) {
  const { data: p, etag } = await api("GET", "/profiles/" + id);
  const text = /** @type {HTMLTextAreaElement} */ (el("textarea", { id: "spec", spellcheck: "false", "aria-label": "Specification (JSON)" }));
  text.value = JSON.stringify(p.specification, null, 2);
  const report = el("div");
  const save = el("button", { type: "button", class: "ghost" }, ["Save as new revision"]);
  const validate = el("button", { type: "button" }, ["Validate desired revision"]);
  host.replaceChildren(el("div", { class: "card" }, [
    el("h2", {}, [p.name]),
    el("p", { class: "muted mono" }, ["desired " + p.desired_revision_id + " · active " + (p.active_revision_id || "none") + " · digest " + p.config_digest.slice(0, 16)]),
    el("p", { class: "muted" }, ["Secrets are secret:// references only. Saving creates an immutable revision; it is not activated until validated and activated."]),
    text,
    el("div", { class: "row" }, [save, validate]),
    report,
  ]));
  save.addEventListener("click", async () => {
    try {
      const spec = JSON.parse(text.value);
      await api("PATCH", "/profiles/" + id, {
        body: { specification: spec }, contentType: "application/merge-patch+json", headers: { "If-Match": etag || "" },
      });
      notice("Saved new desired revision.");
      await renderProfile(id, host);
    } catch (e) {
      notice("Save failed: " + /** @type {Error} */ (e).message, true);
    }
  });
  validate.addEventListener("click", async () => {
    try {
      const { data: r } = await api("POST", "/profiles/" + id + "/validate", {
        body: { target_revision_id: p.desired_revision_id }, headers: { "If-Match": etag || "" },
      });
      showReport(r, id, etag || "", report, host);
    } catch (e) {
      notice("Validation failed: " + /** @type {Error} */ (e).message, true);
    }
  });
}

/** @param {any} r @param {string} id @param {string} etag @param {HTMLElement} out @param {HTMLElement} host */
function showReport(r, id, etag, out, host) {
  /** @param {string} title @param {string[]} items */
  const list = (title, items) => items.length ? el("div", {}, [el("strong", {}, [title]), el("ul", { class: "plain" }, items.map((x) => el("li", {}, [x])))]) : null;
  const activate = el("button", { type: "button" }, ["Activate this exact revision"]);
  /** @type {HTMLButtonElement} */ (activate).disabled = !r.valid || !session.scopes.includes("profiles:activate");
  out.replaceChildren(el("div", { class: "card" }, [
    el("h2", {}, [r.valid ? "Validation passed" : "Validation failed"]),
    el("p", { class: "muted mono" }, ["revision " + r.target_revision_id + " · expires " + r.expires_at + " · epoch " + r.security_epoch]),
    list("Errors", r.errors),
    list("Warnings", r.warnings),
    list("Security diff", r.security_diff),
    el("div", { class: "row" }, [activate]),
  ]));
  activate.addEventListener("click", async () => {
    try {
      const { data: job } = await api("POST", "/profiles/" + id + "/activate", {
        body: { target_revision_id: r.target_revision_id, config_digest: r.config_digest, validation_id: r.validation_id },
        headers: { "If-Match": etag, "Idempotency-Key": uuidKey() },
      });
      await pollJob(job.id);
      await renderProfile(id, host);
    } catch (e) {
      notice("Activation failed: " + /** @type {Error} */ (e).message, true);
    }
  });
}

/** @param {string} jobId */
async function pollJob(jobId) {
  for (let i = 0; i < 60; i++) {
    const { data: j } = await api("GET", "/jobs/" + jobId);
    if (j.status === "succeeded") { notice("Activation succeeded: committed, published and durably applied."); return; }
    if (j.status === "failed" || j.status === "cancelled") { notice("Job " + j.status + " (" + (j.safe_error_code || "no code") + "); live policy unchanged.", true); return; }
    if (j.status === "reconciling") { notice("Committed but not yet applied: reconciling. New admissions are held; use the local CLI to inspect.", true); return; }
    await new Promise((res) => setTimeout(res, 500));
  }
  notice("Job still running; check again later.", true);
}

async function renderNodes() {
  const v = root();
  const { data } = await api("GET", "/nodes?limit=100");
  const rows = data.items.map((/** @type {any} */ n) => {
    const btn = el("button", { type: "button", class: "danger" }, ["Revoke"]);
    /** @type {HTMLButtonElement} */ (btn).disabled = n.status === "revoked" || !session.scopes.includes("identity:revoke");
    btn.addEventListener("click", async () => {
      if (!confirm("Revoke " + n.name + "? New streams and handshakes will be refused and its sessions closed.")) return;
      try {
        const { etag } = await api("GET", "/nodes/" + n.id);
        const { data: job } = await api("POST", "/nodes/" + n.id + "/revoke", { headers: { "If-Match": etag || "", "Idempotency-Key": uuidKey() } });
        notice("Revocation job " + job.status + ".");
        setTimeout(() => view("nodes"), 600);
      } catch (e) {
        notice("Revoke failed: " + /** @type {Error} */ (e).message, true);
      }
    });
    return el("tr", {}, [el("td", {}, [n.name]), el("td", {}, [n.status]), el("td", { class: "mono" }, [n.id]), el("td", {}, [btn])]);
  });
  v.append(el("div", { class: "card" }, [
    el("h2", {}, ["Enrolled nodes"]),
    rows.length ? el("table", {}, [el("thead", {}, [el("tr", {}, [el("th", {}, ["Name"]), el("th", {}, ["Status"]), el("th", {}, ["ID"]), el("th", {}, [""])])]), el("tbody", {}, rows)]) : el("p", { class: "muted" }, ["No nodes enrolled yet."]),
  ]));
  const role = el("select", { id: "role" }, [el("option", { value: "agent" }, ["Agent (client)"]), el("option", { value: "gateway" }, ["Gateway"])]);
  const create = el("button", { type: "button" }, ["Create one-time invitation"]);
  /** @type {HTMLButtonElement} */ (create).disabled = !session.scopes.includes("nodes:write");
  const out = el("div");
  v.append(el("div", { class: "card" }, [
    el("h2", {}, ["Enroll a node"]),
    el("p", { class: "muted" }, ["The node generates its own key and CSR (aegisctl pki csr). The invitation is shown once and expires unused if lost."]),
    el("label", { for: "role" }, ["Role"]), role,
    el("div", { class: "row" }, [create]),
    out,
  ]));
  create.addEventListener("click", async () => {
    try {
      const { data } = await api("POST", "/nodes/enrollment", { body: { role: /** @type {HTMLSelectElement} */ (role).value, expires_in_seconds: 600 } });
      const code = el("code", {}, [data.token]);
      const dismiss = el("button", { type: "button", class: "ghost" }, ["I have copied it — clear"]);
      out.replaceChildren(el("div", { class: "secret", role: "alert" }, [
        el("p", {}, ["One-time invitation (expires " + data.expires_at + "):"]), code, el("div", { class: "row" }, [dismiss]),
      ]));
      dismiss.addEventListener("click", () => out.replaceChildren());
    } catch (e) {
      notice("Enrollment failed: " + /** @type {Error} */ (e).message, true);
    }
  });
}

async function renderAudit() {
  const v = root();
  const { data } = await api("GET", "/audit?limit=100");
  const rows = data.items.map((/** @type {any} */ a) =>
    el("tr", {}, [el("td", {}, [a.timestamp]), el("td", {}, [a.action]), el("td", {}, [a.decision]), el("td", { class: "mono" }, [a.target_type + (a.target_id ? " " + a.target_id.slice(0, 8) : "")])]));
  v.append(el("div", { class: "card" }, [
    el("h2", {}, ["Audit trail (append-only, redacted)"]),
    el("table", {}, [el("thead", {}, [el("tr", {}, [el("th", {}, ["Time"]), el("th", {}, ["Action"]), el("th", {}, ["Decision"]), el("th", {}, ["Target"])])]), el("tbody", {}, rows)]),
  ]));
}

// ---------------------------------------------------------------- wiring

document.getElementById("nav")?.addEventListener("click", (ev) => {
  const t = /** @type {HTMLElement} */ (ev.target);
  const id = t.getAttribute && t.getAttribute("data-view");
  if (id) view(id);
});
document.getElementById("nav")?.addEventListener("keydown", (ev) => {
  const tabs = Array.from(document.querySelectorAll("#nav button"));
  const i = tabs.indexOf(/** @type {Element} */ (document.activeElement));
  if (i < 0) return;
  if (ev.key === "ArrowRight" || ev.key === "ArrowLeft") {
    const n = tabs[(i + (ev.key === "ArrowRight" ? 1 : tabs.length - 1)) % tabs.length];
    /** @type {HTMLElement} */ (n).focus();
    view(/** @type {string} */ (n.getAttribute("data-view")));
  }
});
document.getElementById("logout")?.addEventListener("click", async () => {
  try { await api("POST", "/auth/logout"); } catch { /* already gone */ }
  session.csrf = null;
  session.principal = null;
  session.scopes = [];
  /** @type {HTMLElement} */ (document.getElementById("badges")).replaceChildren();
  showLogin();
});
boot();
