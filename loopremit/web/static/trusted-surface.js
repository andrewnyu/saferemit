// Loop Remit Trusted Surface: the OFW's device key and everything the browser signs.
//
// The device key is a WebCrypto ECDSA P-256 key generated with extractable=false
// and kept in IndexedDB. JavaScript (including ours) can ask it to sign, but can
// never read the private key out of the browser.
//
// Rule this file follows: the browser renders what it signs, from the bytes it
// signs. For the plan, the server sends a draft; we decode the payload *from the
// signing input itself*, recompute every disclosure digest, rebuild the plan from
// those disclosures, render it, and only then sign those exact bytes.

const LoopRemit = (() => {
  const DB_NAME = "loopremit-device", STORE = "keys", KEY_ID = "ofw-device-key";
  const enc = new TextEncoder(), dec = new TextDecoder();

  // ---------------------------------------------------------------- base64url
  const b64url = (bytes) => {
    let s = "";
    new Uint8Array(bytes).forEach((b) => (s += String.fromCharCode(b)));
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  };
  const unb64url = (text) => {
    const s = atob(text.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((text.length + 3) % 4));
    return Uint8Array.from(s, (c) => c.charCodeAt(0));
  };
  const jsonFromB64url = (text) => JSON.parse(dec.decode(unb64url(text)));
  const sha256b64url = async (ascii) => b64url(await crypto.subtle.digest("SHA-256", enc.encode(ascii)));

  // ---------------------------------------------------------------- IndexedDB key store
  const idb = () =>
    new Promise((resolve, reject) => {
      const req = indexedDB.open(DB_NAME, 1);
      req.onupgradeneeded = () => req.result.createObjectStore(STORE);
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  const idbDo = async (mode, fn) => {
    const db = await idb();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, mode);
      const req = fn(tx.objectStore(STORE));
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  };

  async function loadDeviceKey() {
    return (await idbDo("readonly", (s) => s.get(KEY_ID))) || null;
  }

  async function postJSON(url, body) {
    const res = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
    return data;
  }

  // Register (or re-register, idempotently) the public half with the server.
  async function registerDeviceKey(stored) {
    const { kid } = await postJSON("/api/ofw/device-key", { jwk: stored.publicJwk, label: navigator.userAgent.slice(0, 60) });
    if (kid !== stored.kid) {
      stored.kid = kid;
      await idbDo("readwrite", (s) => s.put(stored, KEY_ID));
    }
    return stored;
  }

  async function createDeviceKey() {
    const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
    const jwk = await crypto.subtle.exportKey("jwk", pair.publicKey); // public keys are always exportable
    const publicJwk = { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y };
    const stored = { privateKey: pair.privateKey, publicKey: pair.publicKey, publicJwk, kid: null, created: Date.now() };
    await idbDo("readwrite", (s) => s.put(stored, KEY_ID));
    return registerDeviceKey(stored);
  }

  async function signAscii(stored, ascii) {
    const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, stored.privateKey, enc.encode(ascii));
    return b64url(sig); // WebCrypto returns raw r||s (64 bytes): exactly the JOSE ES256 format
  }

  // ---------------------------------------------------------------- SD-JWT draft verification
  // Mirrors loopremit/crypto/sdjwt.py:resolve(): every disclosure must be referenced
  // exactly once by a digest in the signed payload.
  async function resolveDraft(draft) {
    const [h64, p64] = draft.signing_input.split(".");
    const header = jsonFromB64url(h64);
    const payload = jsonFromB64url(p64); // what we render comes from the bytes we sign
    const byDigest = new Map();
    for (const encoded of draft.disclosures) {
      const digest = await sha256b64url(encoded);
      byDigest.set(digest, { encoded, value: jsonFromB64url(encoded) });
    }
    const used = new Set();
    const take = (digest) => {
      const d = byDigest.get(digest);
      if (d) {
        if (used.has(digest)) throw new Error("digest referenced twice");
        used.add(digest);
      }
      return d;
    };
    const walk = (node) => {
      if (Array.isArray(node)) {
        const out = [];
        for (const el of node) {
          if (el && typeof el === "object" && !Array.isArray(el) && Object.keys(el).length === 1 && "..." in el) {
            const d = take(el["..."]);
            if (d) out.push(walk(d.value[1]));
          } else out.push(walk(el));
        }
        return out;
      }
      if (node && typeof node === "object") {
        const out = {};
        for (const [k, v] of Object.entries(node)) if (k !== "_sd") out[k] = walk(v);
        for (const digest of node._sd || []) {
          const d = take(digest);
          if (d) {
            if (d.value.length !== 3 || d.value[1] in out) throw new Error("bad property disclosure");
            out[d.value[1]] = walk(d.value[2]);
          }
        }
        return out;
      }
      return node;
    };
    const claims = walk(payload);
    if (used.size !== byDigest.size) throw new Error("a disclosure is not referenced by the payload");
    if (payload._sd_alg !== "sha-256") throw new Error("unexpected _sd_alg");
    delete claims._sd_alg;
    return { header, payload, claims, disclosureCount: byDigest.size };
  }

  // ---------------------------------------------------------------- rendering helpers
  const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
  const peso = (minor) => "₱" + (minor / 100).toLocaleString("en-PH", { minimumFractionDigits: 2, maximumFractionDigits: 2 });
  const pesoMajor = (major) => "₱" + Number(major).toLocaleString("en-PH", { minimumFractionDigits: 2, maximumFractionDigits: 2 });
  const date = (epoch) => new Date(epoch * 1000).toLocaleString("en-PH", { dateStyle: "medium", timeStyle: "short" });

  function renderMandate(content, header) {
    const byType = Object.fromEntries(content.constraints.map((c) => [c.type, c]));
    const payees = byType["payment.allowed_payees"]?.allowed || [];
    const caps = byType["loopremit.category_cap"]?.caps || [];
    const range = byType["payment.amount_range"], budget = byType["payment.budget"];
    const rec = byType["payment.agent_recurrence"], win = byType["payment.execution_date"];
    const step = byType["loopremit.step_up_over"], ev = byType["loopremit.evidence_required"];
    return `
      <dl class="kv">
        <dt>Type</dt><dd><code>${esc(content.vct)}</code> signed with your device key <code>${esc(header.kid.slice(0, 12))}…</code></dd>
        <dt>Bill agent key (cnf)</dt><dd><code>${esc(content.cnf.jwk.x.slice(0, 16))}…</code> is the only key that may use this plan</dd>
        <dt>Valid until</dt><dd>${esc(date(content.exp))}</dd>
        <dt>Monthly budget</dt><dd>${esc(pesoMajor(budget.max))} · at most ${esc(rec.max_occurrences)} payments per month</dd>
        <dt>Each payment</dt><dd>${esc(peso(range.min))} to ${esc(peso(range.max))}</dd>
        <dt>Pay between</dt><dd>${esc(win.not_before)} and ${esc(win.not_after)}</dd>
        <dt>Ask me first above</dt><dd>${esc(peso(step.amount))} (I sign each one)</dd>
        <dt>Evidence</dt><dd>bill photo hash bound to every payment; checks: ${esc(ev.checks.join(", "))}</dd>
      </dl>
      <h4>Allowed payees (${payees.length})</h4>
      <ul class="plain">${payees.map((p) => `<li><b>${esc(p.name)}</b> <span class="tag">${esc(p.category)}</span><br>
        <small>account ${esc(p.account_number)} · pays out to ${esc(p.paypal_email)}</small></li>`).join("")}</ul>
      <h4>Category caps</h4>
      <ul class="plain">${caps.map((c) => `<li><b>${esc(c.category)}</b>: ${esc(peso(c.max))} ${c.period === "WINDOW"
        ? `${esc(c.label || "")} (${esc(c.not_before)} to ${esc(c.not_after)})` : "per month"}</li>`).join("")}</ul>`;
  }

  // ---------------------------------------------------------------- flows
  async function signPlan(form, ui) {
    const stored = await loadDeviceKey();
    if (!stored) throw new Error("No device key in this browser. Go to onboarding first.");
    await registerDeviceKey(stored);
    const { plan_id, draft } = await postJSON("/api/ofw/plan/draft", { ...form, kid: stored.kid });
    const resolved = await resolveDraft(draft);
    if (resolved.header.kid !== stored.kid) throw new Error("draft names a different device key");
    const content = resolved.claims.delegate_payload[0];
    ui.show(renderMandate(content, resolved.header), resolved, draft);
    await ui.confirmed();
    const signature = await signAscii(stored, draft.signing_input);
    return postJSON(`/api/ofw/plan/${plan_id}/sign`, { signature });
  }

  async function signDecision(approvalId, billId, decision, closedMandate) {
    const stored = await loadDeviceKey();
    if (!stored) throw new Error("No device key in this browser. Go to onboarding first.");
    await registerDeviceKey(stored);
    const header = { alg: "ES256", typ: "loopremit-step-up+jwt", kid: stored.kid };
    const payload = { vct: "loopremit.step_up_decision.1", decision, closed_mandate: closedMandate || {}, bill_id: billId,
                      iat: Math.floor(Date.now() / 1000) };
    const signingInput = `${b64url(enc.encode(JSON.stringify(header)))}.${b64url(enc.encode(JSON.stringify(payload)))}`;
    const jws = `${signingInput}.${await signAscii(stored, signingInput)}`;
    return postJSON(`/api/ofw/approvals/${approvalId}`, { decision_jws: jws });
  }

  return { loadDeviceKey, createDeviceKey, registerDeviceKey, signPlan, signDecision, resolveDraft, peso, esc };
})();
