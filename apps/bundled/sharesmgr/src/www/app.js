(() => {
    "use strict";

    const $ = (id) => document.getElementById(id);

    function sharesT(key, params, fallback) {
        try {
            const api = window.PQNAS_I18N;
            if (api && typeof api.t === "function") {
                return api.t(key, params || null, fallback);
            }
        } catch (_) {}

        let out = String(fallback || key || "");
        const p = params || {};
        for (const name of Object.keys(p)) {
            out = out.split(`{${name}}`).join(String(p[name]));
        }
        return out;
    }

    const appVersionEl = $("appVersion");

    const btnRefresh = $("btnRefresh");
    const btnRevokeExpired = $("btnRevokeExpired");
    const btnClear = $("btnClear");

    const toastArea = $("toastArea");
    const statusLine = $("statusLine");

    const q = $("q");
    const state = $("state");
    const sort = $("sort");
    const showToken = $("showToken");

    const standardCard = $("standardCard");
    const workspaceCard = $("workspaceCard");
    const pqCard = $("pqCard");

    const btnToggleStandard = $("btnToggleStandard");
    const btnToggleWorkspace = $("btnToggleWorkspace");
    const btnTogglePq = $("btnTogglePq");

    const countPillStandard = $("countPillStandard");
    const countPillWorkspace = $("countPillWorkspace");
    const countPillPq = $("countPillPq");

    const thTokenStandard = $("thTokenStandard");
    const thTokenWorkspace = $("thTokenWorkspace");
    const thTokenPq = $("thTokenPq");

    const tbodyStandard = $("tbodyStandard");
    const tbodyWorkspace = $("tbodyWorkspace");
    const tbodyPq = $("tbodyPq");

    const OPEN_STD_KEY = "sharesmgr_standard_open_v1";
    const OPEN_WS_KEY = "sharesmgr_workspace_open_v1";
    const OPEN_PQ_KEY = "sharesmgr_pq_open_v1";

    let shares = [];
    let lastLoadedAt = 0;

    function nowMs() { return Date.now(); }

    function toast(kind, msg) {
        if (!toastArea) return;
        const el = document.createElement("div");
        el.className = "toast " + (kind === "err" ? "err" : "ok");
        el.textContent = msg;
        toastArea.prepend(el);
        setTimeout(() => { try { el.remove(); } catch {} }, 5500);
    }

    function fmtTsMaybe(iso) {
        if (!iso) return "—";
        return iso;
    }

    function escapeHtml(s) {
        return String(s).replace(/[&<>"']/g, (c) => ({
            "&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"
        }[c]));
    }

    function escapeAttr(s) {
        return escapeHtml(s).replace(/`/g, "&#96;");
    }

    async function copyText(text) {
        try {
            await navigator.clipboard.writeText(text);
            return true;
        } catch {
            try {
                const ta = document.createElement("textarea");
                ta.value = text;
                ta.style.position = "fixed";
                ta.style.left = "-2000px";
                document.body.appendChild(ta);
                ta.select();
                document.execCommand("copy");
                ta.remove();
                return true;
            } catch {
                return false;
            }
        }
    }

    async function apiJson(method, url, bodyObj) {
        const opts = {
            method,
            credentials: "include",
            cache: "no-store",
            headers: {}
        };
        if (bodyObj !== undefined) {
            opts.headers["Content-Type"] = "application/json; charset=utf-8";
            opts.body = JSON.stringify(bodyObj);
        }

        let r;
        try {
            r = await fetch(url, opts);
        } catch (e) {
            const msg = (e && e.message) ? e.message : String(e);
            if (statusLine) statusLine.textContent = sharesT("sharesmgr.network_error_calling", { url, msg }, "Network error calling {url}: {msg}");
            console.error("fetch failed:", url, e);
            throw e;
        }

        let j = null;
        try { j = await r.json(); } catch {}
        return { r, j };
    }

    async function getAppVersion() {
        const m = location.pathname.match(/^\/apps\/([^/]+)\/([^/]+)\//);
        if (m && m[2]) return decodeURIComponent(m[2]);

        for (const url of ["../manifest.json", "./manifest.json"]) {
            try {
                const r = await fetch(url, {
                    cache: "no-store",
                    headers: { "Accept": "application/json" }
                });
                if (!r.ok) continue;
                const j = await r.json();
                const ver = j && typeof j.version === "string" ? j.version.trim() : "";
                if (ver) return ver;
            } catch (_) {}
        }

        return "";
    }

    async function loadVersion() {
        if (!appVersionEl) return;

        try {
            const ver = await getAppVersion();
            if (!ver) {
                appVersionEl.hidden = true;
                return;
            }

            appVersionEl.textContent = ` • v${ver}`;
            appVersionEl.title = sharesT("sharesmgr.version_title", { version: ver }, "Shares Manager {version}");
            appVersionEl.hidden = false;
        } catch (e) {
            console.warn("version lookup failed:", e);
        }
    }

    function isExpired(s) {
        if (!s.expires_at) return false;
        const t = Date.parse(s.expires_at);
        if (!Number.isFinite(t)) return false;
        return t <= Date.now();
    }

    function hasNoExpiry(s) {
        return !s.expires_at;
    }

    function expiredShares(list) {
        return (list || []).filter(s => !!s && !!s.token && isExpired(s));
    }

    function shareUrlAbs(s) {
        const base = window.location.origin;
        return base + (s.url || ("/s/" + s.token));
    }

    function inviteUrlAbs(s) {
        if (!s || !s.invite_url) return "";
        if (/^https?:\/\//i.test(String(s.invite_url))) return String(s.invite_url);
        return window.location.origin + String(s.invite_url);
    }

    function pqModeOf(s) {
        return String(s?.pq_mode || s?.mode || s?.kind || "").trim();
    }

    function isPqShare(s) {
        const mode = pqModeOf(s).toLowerCase();
        if (mode.includes("pq")) return true;
        if (s?.invite_url) return true;
        if (s?.invite_id) return true;
        if (s?.pq_state) return true;
        if (s?.recipient_count != null) return true;
        if (Array.isArray(s?.recipient_device_ids)) return true;
        return false;
    }
    function isWorkspaceShare(s) {
        if (!s || isPqShare(s)) return false;
        const scope = String(s.scope_kind || "").trim().toLowerCase();
        return scope === "workspace" || !!s.workspace_id;
    }
    function splitShares(list) {
        const standard = [];
        const workspace = [];
        const pq = [];

        for (const s of (list || [])) {
            if (isPqShare(s)) {
                pq.push(s);
            } else if (isWorkspaceShare(s)) {
                workspace.push(s);
            } else {
                standard.push(s);
            }
        }

        return { standard, workspace, pq };
    }

    function pqStateOf(s) {
        const st = String(s?.pq_state || s?.state || "").trim().toLowerCase();

        // Keep terminal backend states.
        if (st === "revoked") return "revoked";
        if (st === "expired") return "expired";

        // Frontend safety: if expiry time is in the past, show expired.
        if (isExpired(s)) return "expired";

        if (!st) {
            if (s?.invite_url) return "pending";
            return "active";
        }
        return st;
    }

    function pqStateBadgeHtml(s) {
        const st = pqStateOf(s);
        if (st === "active") return `<span class="badge badgeOk">${escapeHtml(sharesT("sharesmgr.active_one", null, "active"))}</span>`;
        if (st === "pending" || st === "pending_enrollment") return `<span class="badge badgeWarn">${escapeHtml(sharesT("sharesmgr.pending", null, "pending"))}</span>`;
        if (st === "claimed") return `<span class="badge badgeOk">${escapeHtml(sharesT("sharesmgr.claimed", null, "claimed"))}</span>`;
        if (st === "revoked") return `<span class="badge badgeDanger">${escapeHtml(sharesT("sharesmgr.revoked_one", null, "revoked"))}</span>`;
        if (st === "expired") return `<span class="badge badgeDanger">${escapeHtml(sharesT("sharesmgr.expired_one", null, "expired"))}</span>`;
        return `<span class="badge">${escapeHtml(st || sharesT("common.unknown", null, "unknown"))}</span>`;
    }
    function shortenMiddle(s, max = 24) {
        s = String(s || "");
        if (!s || s.length <= max) return s;
        const keep = Math.max(6, Math.floor((max - 3) / 2));
        return s.slice(0, keep) + "..." + s.slice(s.length - keep);
    }
    function normalizeKemAlgUi(kem) {
        const v = String(kem || "").trim();
        if (!v) return "";
        if (v === "ml-kem-768" || v === "mlkem768" || v === "MLKEM768") return "ML-KEM-768";
        if (v === "x25519" || v === "X25519") return "X25519";
        return v;
    }
    function firstPqRecipient(s) {
        if (Array.isArray(s?.recipients) && s.recipients.length) return s.recipients[0];
        if (Array.isArray(s?.recipient_device_ids) && s.recipient_device_ids.length) {
            return {
                recipient_device_id: s.recipient_device_ids[0],
                label: "",
                note: "",
                state: ""
            };
        }
        return null;
    }

    function pqRecipientInfoHtml(s) {
        const r = firstPqRecipient(s);
        if (!r) return "";

        const label = String(r.label || "").trim();
        const note = String(r.note || "").trim();
        const rid = String(r.recipient_device_id || "").trim();
        const kem = normalizeKemAlgUi(r.kem_alg);
        const extraCount = Math.max(0, (Number(s?.recipient_count || 0) - 1));

        let html = `<div style="margin-top:6px;display:flex;flex-direction:column;gap:4px">`;

        if (label) {
            html += `<div><span class="badge badgeOk">${escapeHtml(label)}</span></div>`;
        }

        if (kem === "ML-KEM-768") {
            html += `<div><span class="badge badgeOk">${escapeHtml(sharesT("sharesmgr.post_quantum", null, "Post-Quantum"))}</span> <span class="badge">${escapeHtml(kem)}</span></div>`;
        } else if (kem) {
            html += `<div><span class="badge badgeWarn">${escapeHtml(kem)}</span></div>`;
        }

        if (note) {
            html += `<div style="font-size:12px;color:var(--fg-dim, #9aa4b2)">${escapeHtml(note)}</div>`;
        }

        if (rid) {
            html += `<div style="font-size:12px;color:var(--fg-dim, #9aa4b2)" class="mono">${escapeHtml(sharesT("sharesmgr.recipient", null, "recipient"))} ${escapeHtml(shortenMiddle(rid, 26))}</div>`;
        }

        if (extraCount > 0) {
            html += `<div style="font-size:12px;color:var(--fg-dim, #9aa4b2)">${escapeHtml(sharesT("sharesmgr.more_recipients", { count: extraCount }, "+{count} more recipient(s)"))}</div>`;
        }

        html += `</div>`;
        return html;
    }
    function normalStateBadgeHtml(s) {
        if (isExpired(s)) return `<span class="badge badgeDanger">${escapeHtml(sharesT("sharesmgr.expired_one", null, "expired"))}</span>`;
        if (s.expires_at) return `<span class="badge">${escapeHtml(sharesT("sharesmgr.active_one", null, "active"))}</span>`;
        return `<span class="badge badgeDim">${escapeHtml(sharesT("sharesmgr.no_expiry_one", null, "no expiry"))}</span>`;
    }

    function getStoredBool(key, defv) {
        try {
            const v = localStorage.getItem(key);
            if (v === null) return !!defv;
            return v === "1";
        } catch {
            return !!defv;
        }
    }

    function setStoredBool(key, on) {
        try { localStorage.setItem(key, on ? "1" : "0"); } catch {}
    }

    function setSectionOpen(cardEl, btnEl, open, persistKey) {
        if (!cardEl || !btnEl) return;
        cardEl.classList.toggle("collapsed", !open);
        btnEl.setAttribute("aria-expanded", open ? "true" : "false");

        const chev = btnEl.querySelector(".chev");
        const txt = btnEl.querySelector(".txt");

        if (chev) chev.textContent = open ? "▾" : "▸";
        if (txt) txt.textContent = open ? sharesT("common.hide", null, "Hide") : sharesT("common.show", null, "Show");

        if (persistKey) setStoredBool(persistKey, open);
    }

    function initSectionToggles() {
        const stdOpen = getStoredBool(OPEN_STD_KEY, true);
        const wsOpen = getStoredBool(OPEN_WS_KEY, true);
        const pqOpen = getStoredBool(OPEN_PQ_KEY, true);

        setSectionOpen(standardCard, btnToggleStandard, stdOpen, null);
        setSectionOpen(workspaceCard, btnToggleWorkspace, wsOpen, null);
        setSectionOpen(pqCard, btnTogglePq, pqOpen, null);

        btnToggleStandard?.addEventListener("click", () => {
            const nowOpen = standardCard && !standardCard.classList.contains("collapsed");
            setSectionOpen(standardCard, btnToggleStandard, !nowOpen, OPEN_STD_KEY);
        });

        btnToggleWorkspace?.addEventListener("click", () => {
            const nowOpen = workspaceCard && !workspaceCard.classList.contains("collapsed");
            setSectionOpen(workspaceCard, btnToggleWorkspace, !nowOpen, OPEN_WS_KEY);
        });

        btnTogglePq?.addEventListener("click", () => {
            const nowOpen = pqCard && !pqCard.classList.contains("collapsed");
            setSectionOpen(pqCard, btnTogglePq, !nowOpen, OPEN_PQ_KEY);
        });
    }

    async function loadShares() {
        if (statusLine) statusLine.textContent = sharesT("sharesmgr.loading_shares", null, "Loading shares…");

        const { r, j } = await apiJson("GET", "/api/v4/shares/list");
        if (!r.ok || !j || !j.ok || !Array.isArray(j.shares)) {
            shares = [];
            lastLoadedAt = nowMs();

            if (statusLine) {
                if (r.status === 403) {
                    statusLine.textContent = sharesT("sharesmgr.not_allowed", null, "Not allowed (403). This app needs share list access for your account.");
                } else if (r.status === 401) {
                    statusLine.textContent = sharesT("sharesmgr.not_signed_in", null, "Not signed in (401). Open PQ-NAS and sign in.");
                } else {
                    statusLine.textContent = sharesT("sharesmgr.failed_to_load_status", { status: r.status }, "Failed to load shares ({status}).");
                }
            }

            render();
            return;
        }

        shares = j.shares.slice();
        lastLoadedAt = nowMs();
        render();
    }

    async function revokeShare(token) {
        const { r, j } = await apiJson("POST", "/api/v4/shares/revoke", { token });
        if (!r.ok || !j || !j.ok) {
            const msg = (j && (j.message || j.error))
                ? `${j.error || ""} ${j.message || ""}`.trim()
                : sharesT("sharesmgr.revoke_failed_status", { status: r.status }, "revoke failed ({status})");
            throw new Error(msg);
        }
    }
    async function updatePqRecipient(shareToken, recipientDeviceId, patch) {
        const body = {
            share_token: shareToken,
            recipient_device_id: recipientDeviceId
        };

        if (Object.prototype.hasOwnProperty.call(patch || {}, "label")) {
            body.label = patch.label;
        }
        if (Object.prototype.hasOwnProperty.call(patch || {}, "note")) {
            body.note = patch.note;
        }

        const { r, j } = await apiJson("POST", "/api/v4/shares/pq/recipient/update", body);
        if (!r.ok || !j || !j.ok) {
            const msg = (j && (j.message || j.error))
                ? `${j.error || ""} ${j.message || ""}`.trim()
                : sharesT("sharesmgr.recipient_update_failed_status", { status: r.status }, "recipient update failed ({status})");
            throw new Error(msg);
        }
        return j.recipient || null;
    }

    function sharesConfirmModal(opts = {}) {
        return new Promise((resolve) => {
            const options = opts || {};

            const backdrop = document.createElement("div");
            backdrop.className = "sharesConfirmBackdrop";
            backdrop.setAttribute("role", "dialog");
            backdrop.setAttribute("aria-modal", "true");

            const card = document.createElement("div");
            card.className = "sharesConfirmCard";

            const head = document.createElement("div");
            head.className = "sharesConfirmHead";

            const titleWrap = document.createElement("div");

            const title = document.createElement("div");
            title.className = "sharesConfirmTitle";
            title.textContent = options.title || sharesT("sharesmgr.confirm_action", null, "Confirm action");

            const sub = document.createElement("div");
            sub.className = "sharesConfirmSub";
            sub.textContent = options.subtitle || "";

            titleWrap.appendChild(title);
            if (sub.textContent) titleWrap.appendChild(sub);
            head.appendChild(titleWrap);

            const body = document.createElement("div");
            body.className = "sharesConfirmBody";

            const rows = Array.isArray(options.rows) ? options.rows : [];
            for (const row of rows) {
                const k = document.createElement("div");
                k.className = "sharesConfirmKey";
                k.textContent = String(row.label || "");

                const v = document.createElement("div");
                v.className = row.mono ? "sharesConfirmValue mono" : "sharesConfirmValue";
                v.textContent = String(row.value || "");

                body.appendChild(k);
                body.appendChild(v);
            }

            if (options.examples) {
                const label = document.createElement("div");
                label.className = "sharesConfirmKey";
                label.textContent = sharesT("sharesmgr.examples", null, "Examples");

                const value = document.createElement("div");
                value.className = "sharesConfirmValue mono";
                value.textContent = String(options.examples || "");

                body.appendChild(label);
                body.appendChild(value);
            }

            if (options.note) {
                const note = document.createElement("div");
                note.className = "sharesConfirmNote";
                note.textContent = String(options.note || "");
                body.appendChild(note);
            }

            const foot = document.createElement("div");
            foot.className = "sharesConfirmFoot";

            const spacer = document.createElement("div");
            spacer.style.flex = "1 1 auto";

            const cancelBtn = document.createElement("button");
            cancelBtn.type = "button";
            cancelBtn.className = "btn btnGhost";
            cancelBtn.textContent = options.cancelText || sharesT("common.cancel", null, "Cancel");

            const okBtn = document.createElement("button");
            okBtn.type = "button";
            okBtn.className = options.danger ? "btn btnDanger" : "btn";
            okBtn.textContent = options.confirmText || sharesT("common.ok", null, "OK");

            foot.appendChild(spacer);
            foot.appendChild(cancelBtn);
            foot.appendChild(okBtn);

            card.appendChild(head);
            card.appendChild(body);
            card.appendChild(foot);
            backdrop.appendChild(card);
            document.body.appendChild(backdrop);

            const close = (value) => {
                document.removeEventListener("keydown", onKey, true);
                backdrop.remove();
                resolve(!!value);
            };

            const onKey = (ev) => {
                if (ev.key === "Escape") {
                    ev.preventDefault();
                    ev.stopPropagation();
                    close(false);
                    return;
                }

                if (ev.key === "Enter") {
                    ev.preventDefault();
                    ev.stopPropagation();
                    close(true);
                }
            };

            document.addEventListener("keydown", onKey, true);

            backdrop.addEventListener("click", (ev) => {
                if (ev.target === backdrop) close(false);
            });

            cancelBtn.addEventListener("click", () => close(false));
            okBtn.addEventListener("click", () => close(true));

            window.setTimeout(() => {
                if (options.danger) cancelBtn.focus();
                else okBtn.focus();
            }, 0);
        });
    }

    function sharesRecipientEditModal(opts = {}) {
        return new Promise((resolve) => {
            const options = opts || {};

            const backdrop = document.createElement("div");
            backdrop.className = "sharesConfirmBackdrop";
            backdrop.setAttribute("role", "dialog");
            backdrop.setAttribute("aria-modal", "true");

            const card = document.createElement("div");
            card.className = "sharesConfirmCard";

            const head = document.createElement("div");
            head.className = "sharesConfirmHead";

            const titleWrap = document.createElement("div");

            const title = document.createElement("div");
            title.className = "sharesConfirmTitle";
            title.textContent = sharesT("sharesmgr.rename_recipient", null, "Rename recipient");

            const sub = document.createElement("div");
            sub.className = "sharesConfirmSub";
            sub.textContent = sharesT("sharesmgr.rename_recipient_help", null, "Update the label and note shown for this PQ recipient.");

            titleWrap.appendChild(title);
            titleWrap.appendChild(sub);
            head.appendChild(titleWrap);

            const body = document.createElement("div");
            body.className = "sharesConfirmBody";

            const labelK = document.createElement("div");
            labelK.className = "sharesConfirmKey";
            labelK.textContent = sharesT("sharesmgr.recipient_label", null, "Recipient label");

            const labelWrap = document.createElement("div");
            labelWrap.className = "sharesConfirmValue";

            const labelInput = document.createElement("input");
            labelInput.className = "inp";
            labelInput.type = "text";
            labelInput.value = String(options.label || "");
            labelInput.placeholder = sharesT("sharesmgr.recipient_label_placeholder", null, "Name shown for this recipient");

            labelWrap.appendChild(labelInput);

            const noteK = document.createElement("div");
            noteK.className = "sharesConfirmKey";
            noteK.textContent = sharesT("sharesmgr.recipient_note", null, "Recipient note");

            const noteWrap = document.createElement("div");
            noteWrap.className = "sharesConfirmValue";

            const noteInput = document.createElement("textarea");
            noteInput.className = "inp";
            noteInput.rows = 4;
            noteInput.value = String(options.note || "");
            noteInput.placeholder = sharesT("sharesmgr.recipient_note_placeholder", null, "Optional private note");
            noteInput.style.resize = "vertical";
            noteInput.style.minHeight = "92px";

            noteWrap.appendChild(noteInput);

            body.appendChild(labelK);
            body.appendChild(labelWrap);
            body.appendChild(noteK);
            body.appendChild(noteWrap);

            const foot = document.createElement("div");
            foot.className = "sharesConfirmFoot";

            const spacer = document.createElement("div");
            spacer.style.flex = "1 1 auto";

            const cancelBtn = document.createElement("button");
            cancelBtn.type = "button";
            cancelBtn.className = "btn btnGhost";
            cancelBtn.textContent = sharesT("common.cancel", null, "Cancel");

            const okBtn = document.createElement("button");
            okBtn.type = "button";
            okBtn.className = "btn";
            okBtn.textContent = sharesT("common.save", null, "Save");

            foot.appendChild(spacer);
            foot.appendChild(cancelBtn);
            foot.appendChild(okBtn);

            card.appendChild(head);
            card.appendChild(body);
            card.appendChild(foot);
            backdrop.appendChild(card);
            document.body.appendChild(backdrop);

            const close = (value) => {
                document.removeEventListener("keydown", onKey, true);
                try { backdrop.remove(); } catch (_) {}
                resolve(value);
            };

            const save = () => close({
                label: String(labelInput.value || ""),
                note: String(noteInput.value || "")
            });

            const onKey = (ev) => {
                if (ev.key === "Escape") {
                    ev.preventDefault();
                    ev.stopPropagation();
                    close(null);
                    return;
                }

                if (ev.key === "Enter" && (ev.ctrlKey || ev.metaKey)) {
                    ev.preventDefault();
                    ev.stopPropagation();
                    save();
                }
            };

            document.addEventListener("keydown", onKey, true);

            backdrop.addEventListener("click", (ev) => {
                if (ev.target === backdrop) close(null);
            });

            cancelBtn.addEventListener("click", () => close(null));
            okBtn.addEventListener("click", save);

            window.setTimeout(() => labelInput.focus(), 0);
        });
    }

    function injectSharesConfirmCss() {
        if (document.getElementById("sharesConfirmCss")) return;

        const style = document.createElement("style");
        style.id = "sharesConfirmCss";
        style.textContent = `
.sharesConfirmBackdrop{
    position:fixed;
    inset:0;
    z-index:10000;
    display:flex;
    align-items:center;
    justify-content:center;
    padding:18px;
    background:rgba(0,0,0,0.55);
    backdrop-filter:blur(6px);
    -webkit-backdrop-filter:blur(6px);
}

.sharesConfirmCard{
    width:min(620px, calc(100vw - 24px));
    max-height:min(82vh, 900px);
    display:flex;
    flex-direction:column;
    overflow:hidden;
    border:1px solid var(--border2);
    border-radius:18px;
    background:linear-gradient(180deg, var(--panel2), var(--panel));
    box-shadow:var(--shadow);
    color:var(--fg);
}

.sharesConfirmHead{
    display:flex;
    align-items:center;
    justify-content:space-between;
    gap:12px;
    padding:14px 16px;
    border-bottom:1px solid var(--border2);
    background:rgba(0,0,0,0.16);
}

.sharesConfirmTitle{
    font-weight:950;
    letter-spacing:.2px;
}

.sharesConfirmSub{
    margin-top:3px;
    font-size:12px;
    color:var(--fg-dim);
}

.sharesConfirmBody{
    padding:16px;
    display:grid;
    grid-template-columns:130px minmax(0, 1fr);
    gap:10px 14px;
    overflow:auto;
    min-height:0;
}

.sharesConfirmKey{
    color:rgba(var(--fg-rgb),0.70);
    font-weight:850;
}

.sharesConfirmValue{
    color:rgba(var(--fg-rgb),0.95);
    overflow-wrap:anywhere;
    white-space:pre-wrap;
}

.sharesConfirmNote{
    grid-column:1 / -1;
    padding:10px 12px;
    border:1px solid rgba(var(--warn-rgb),0.35);
    border-radius:14px;
    background:rgba(var(--warn-rgb),0.10);
    color:var(--fg);
    font-weight:850;
}

.sharesConfirmFoot{
    display:flex;
    align-items:center;
    gap:12px;
    padding:12px 16px;
    border-top:1px solid var(--border2);
    background:rgba(0,0,0,0.12);
}

html[data-theme="bright"] .sharesConfirmBackdrop{
    background:rgba(255,255,255,0.38);
}
`;
        document.head.appendChild(style);
    }

    async function revokeExpired() {
        const exp = expiredShares(shares);

        if (!exp.length) {
            toast("ok", sharesT("sharesmgr.no_expired_to_revoke", null, "No expired shares to revoke."));
            return;
        }

        const sample = exp.slice(0, 5).map(s => s.path || "(no path)").join("\n");
        injectSharesConfirmCss();

        const ok = await sharesConfirmModal({
            title: sharesT("sharesmgr.revoke_expired_title", null, "Revoke expired shares?"),
            subtitle: sharesT("sharesmgr.revoke_expired_subtitle", null, "This will immediately invalidate expired share URLs."),
            rows: [
                { label: sharesT("sharesmgr.expired_shares", null, "Expired shares"), value: String(exp.length) },
            ],
            examples: sample + (exp.length > 5 ? `\n… ${sharesT("sharesmgr.more_count", { count: exp.length - 5 }, "+{count} more")}` : ""),
            note: sharesT("sharesmgr.revoked_links_note", null, "Revoked links cannot be used again."),
            confirmText: sharesT("sharesmgr.revoke_expired_count", { count: exp.length }, "Revoke expired ({count})"),
            cancelText: sharesT("common.cancel", null, "Cancel"),
            danger: true,
        });

        if (!ok) return;

        btnRevokeExpired.disabled = true;
        btnRefresh.disabled = true;

        let okCount = 0;
        let failCount = 0;

        try {
            for (const s of exp) {
                try {
                    await revokeShare(s.token);
                    okCount++;
                } catch {
                    failCount++;
                }
            }

            if (okCount) toast("ok", sharesT("sharesmgr.revoked_expired_count", { count: okCount }, "Revoked {count} expired share(s)."));
            if (failCount) toast("err", sharesT("sharesmgr.failed_revoke_expired_count", { count: failCount }, "Failed to revoke {count} expired share(s)."));

            await loadShares();
        } finally {
            btnRevokeExpired.disabled = false;
            btnRefresh.disabled = false;
        }
    }

    function applyFilters(list) {
        const qq = (q?.value || "").trim().toLowerCase();
        const st = state?.value || "all";

        let out = list.slice();

        if (qq) {
            out = out.filter(s => {
                const recipientParts = Array.isArray(s?.recipients)
                    ? s.recipients.map(r => [
                        r?.recipient_device_id || "",
                        r?.label || "",
                        r?.note || "",
                        r?.state || "",
                        r?.kem_alg || ""
                    ].join("\n")).join("\n")
                    : "";

                const parts = [
                    s.path || "",
                    s.token || "",
                    s.url || "",
                    s.invite_url || "",
                    s.invite_id || "",
                    s.pq_state || "",
                    s.mode || "",
                    s.pq_mode || "",
                    s.kind || "",
                    s.scope_kind || "",
                    s.workspace_id || "",
                    s.workspace_name || "",
                    recipientParts
                ].join("\n").toLowerCase();
                return parts.includes(qq);
            });
        }

        if (st === "active") out = out.filter(s => !isExpired(s));
        else if (st === "expired") out = out.filter(s => isExpired(s));
        else if (st === "noexpiry") out = out.filter(s => hasNoExpiry(s));

        return out;
    }

    function applySort(list) {
        const mode = sort?.value || "created_desc";

        const parseCreated = (s) => Date.parse(s.created_at || "") || 0;
        const parseExpires = (s) => {
            if (!s.expires_at) return Number.POSITIVE_INFINITY;
            const t = Date.parse(s.expires_at);
            return Number.isFinite(t) ? t : Number.POSITIVE_INFINITY;
        };

        const out = list.slice();

        out.sort((a, b) => {
            if (mode === "created_desc") return parseCreated(b) - parseCreated(a);
            if (mode === "created_asc") return parseCreated(a) - parseCreated(b);
            if (mode === "expires_asc") return parseExpires(a) - parseExpires(b);
            if (mode === "downloads_desc") return (b.downloads || 0) - (a.downloads || 0);
            if (mode === "path_asc") return (a.path || "").localeCompare(b.path || "");
            return 0;
        });

        return out;
    }

    function td(text, cls) {
        const el = document.createElement("td");
        if (cls) el.className = cls;
        el.textContent = text;
        return el;
    }

    function tdHtml(html, cls) {
        const el = document.createElement("td");
        if (cls) el.className = cls;
        el.innerHTML = html;
        return el;
    }

    function makeActionButton(text, className, onClick) {
        const btn = document.createElement("button");
        btn.className = className || "btn";
        btn.textContent = text;
        btn.onclick = onClick;
        return btn;
    }

    function renderEmpty(tbodyEl, text, colSpan) {
        if (!tbodyEl) return;
        tbodyEl.innerHTML = "";
        const tr = document.createElement("tr");
        const cell = document.createElement("td");
        cell.colSpan = colSpan;
        cell.className = "empty";
        cell.textContent = text;
        tr.appendChild(cell);
        tbodyEl.appendChild(tr);
    }

    function renderStandardRows(list, showTok) {
        if (!tbodyStandard) return;

        tbodyStandard.innerHTML = "";

        if (!list.length) {
            renderEmpty(tbodyStandard, shares.length ? sharesT("sharesmgr.no_normal_match", null, "No normal shares match the current filter.") : sharesT("sharesmgr.no_shares_yet", null, "No shares yet."), showTok ? 8 : 7);
            return;
        }

        for (const s of list) {
            const tr = document.createElement("tr");

            tr.appendChild(
                tdHtml(
                    `${escapeHtml(s.path || "")}<div style="margin-top:6px">${normalStateBadgeHtml(s)}</div>`,
                    "colPath"
                )
            );

            tr.appendChild(td((s.type || "—"), "colType"));
            tr.appendChild(td(fmtTsMaybe(s.expires_at), "colExp"));
            tr.appendChild(td(String(s.downloads ?? 0), "colDl"));
            tr.appendChild(td(fmtTsMaybe(s.created_at), "colCreated"));

            const urlAbs = shareUrlAbs(s);
            tr.appendChild(
                tdHtml(
                    `<a class="a mono" href="${escapeAttr(urlAbs)}" target="_blank" rel="noreferrer">
                        ${escapeHtml(s.url || ("/s/" + s.token))}
                     </a>`,
                    "colUrl"
                )
            );

            if (showTok) {
                tr.appendChild(td((s.token || ""), "colToken mono"));
            }

            const act = document.createElement("td");
            act.className = "colAct";

            const wrap = document.createElement("div");
            wrap.className = "actions";

            wrap.appendChild(makeActionButton(sharesT("sharesmgr.copy_link", null, "Copy link"), "btn", async () => {
                const ok = await copyText(urlAbs);
                toast(ok ? "ok" : "err", ok ? sharesT("sharesmgr.copied_link", null, "Copied link.") : sharesT("sharesmgr.copy_failed", null, "Copy failed."));
            }));

            wrap.appendChild(makeActionButton(sharesT("sharesmgr.revoke", null, "Revoke"), "btn btnDanger", async (e) => {
                const btn = e.currentTarget;
                btn.disabled = true;
                try {
                    await revokeShare(s.token);
                    toast("ok", sharesT("sharesmgr.revoked", null, "Revoked."));
                    await loadShares();
                } catch (err) {
                    toast("err", String(err && err.message ? err.message : err));
                } finally {
                    btn.disabled = false;
                }
            }));

            act.appendChild(wrap);
            tr.appendChild(act);

            tbodyStandard.appendChild(tr);
        }
    }
    function renderWorkspaceRows(list, showTok) {
        if (!tbodyWorkspace) return;

        tbodyWorkspace.innerHTML = "";

        if (!list.length) {
            renderEmpty(
                tbodyWorkspace,
                shares.some(isWorkspaceShare)
                    ? sharesT("sharesmgr.no_workspace_match", null, "No workspace shares match the current filter.")
                    : sharesT("sharesmgr.no_workspace_shares", null, "No workspace shares."),
                showTok ? 8 : 7
            );
            return;
        }

        for (const s of list) {
            const tr = document.createElement("tr");

            const wsName = String(s.workspace_name || "").trim();

            const pathHtml =
                `${escapeHtml(s.path || "")}` +
                `<div style="margin-top:6px">` +
                `<span class="badge badgeWarn">${escapeHtml(sharesT("sharesmgr.workspace", null, "workspace"))}</span>` +
                (wsName ? ` <span class="badge">${escapeHtml(wsName)}</span>` : "") +
                ` ${normalStateBadgeHtml(s)}` +
                `</div>`;

            tr.appendChild(tdHtml(pathHtml, "colPath"));
            tr.appendChild(td((s.type || "—"), "colType"));
            tr.appendChild(td(fmtTsMaybe(s.expires_at), "colExp"));
            tr.appendChild(td(String(s.downloads ?? 0), "colDl"));
            tr.appendChild(td(fmtTsMaybe(s.created_at), "colCreated"));

            const urlAbs = shareUrlAbs(s);
            tr.appendChild(
                tdHtml(
                    `<a class="a mono" href="${escapeAttr(urlAbs)}" target="_blank" rel="noreferrer">
                    ${escapeHtml(s.url || ("/s/" + s.token))}
                 </a>`,
                    "colUrl"
                )
            );

            if (showTok) {
                tr.appendChild(td((s.token || ""), "colToken mono"));
            }

            const act = document.createElement("td");
            act.className = "colAct";

            const wrap = document.createElement("div");
            wrap.className = "actions";

            wrap.appendChild(makeActionButton(sharesT("sharesmgr.copy_link", null, "Copy link"), "btn", async () => {
                const ok = await copyText(urlAbs);
                toast(ok ? "ok" : "err", ok ? sharesT("sharesmgr.copied_link", null, "Copied link.") : sharesT("sharesmgr.copy_failed", null, "Copy failed."));
            }));

            wrap.appendChild(makeActionButton(sharesT("sharesmgr.revoke", null, "Revoke"), "btn btnDanger", async (e) => {
                const btn = e.currentTarget;
                btn.disabled = true;
                try {
                    await revokeShare(s.token);
                    toast("ok", sharesT("sharesmgr.revoked", null, "Revoked."));
                    await loadShares();
                } catch (err) {
                    toast("err", String(err && err.message ? err.message : err));
                } finally {
                    btn.disabled = false;
                }
            }));

            act.appendChild(wrap);
            tr.appendChild(act);

            tbodyWorkspace.appendChild(tr);
        }
    }
    function renderPqRows(list, showTok) {
        if (!tbodyPq) return;

        tbodyPq.innerHTML = "";

        if (!list.length) {
            renderEmpty(
                tbodyPq,
                sharesT("sharesmgr.no_pq_shares_yet", null, "No Post-Quantum shares yet."),
                showTok ? 8 : 7
            );
            return;
        }

        for (const s of list) {
            const tr = document.createElement("tr");

            tr.appendChild(
                tdHtml(
                    `${escapeHtml(s.path || "")}${pqRecipientInfoHtml(s)}`,
                    "colPath"
                )
            );

            tr.appendChild(tdHtml(pqStateBadgeHtml(s), "colState"));
            tr.appendChild(td(fmtTsMaybe(s.expires_at), "colExp"));
            tr.appendChild(td(fmtTsMaybe(s.created_at), "colCreated"));

            const inviteAbs = inviteUrlAbs(s);
            if (inviteAbs) {
                tr.appendChild(
                    tdHtml(
                        `<a class="a mono" href="${escapeAttr(inviteAbs)}" target="_blank" rel="noreferrer">${escapeHtml(s.invite_url)}</a>`,
                        "colInvite"
                    )
                );
            } else {
                tr.appendChild(td("—", "colInvite"));
            }

            const shareAbs = shareUrlAbs(s);
            tr.appendChild(
                tdHtml(
                    `<a class="a mono" href="${escapeAttr(shareAbs)}" target="_blank" rel="noreferrer">
                        ${escapeHtml(s.url || ("/s/" + s.token))}
                     </a>`,
                    "colUrl"
                )
            );

            if (showTok) {
                tr.appendChild(td((s.token || ""), "colToken mono"));
            }

            const act = document.createElement("td");
            act.className = "colAct";

            const wrap = document.createElement("div");
            wrap.className = "actions";

            const recipient = firstPqRecipient(s);
            if (recipient && recipient.recipient_device_id) {
                wrap.appendChild(makeActionButton(sharesT("sharesmgr.rename_recipient", null, "Rename recipient"), "btn", async (e) => {
                    const btn = e.currentTarget;
                    const curLabel = String(recipient.label || "").trim();
                    const curNote = String(recipient.note || "").trim();

                    injectSharesConfirmCss();
                    const edit = await sharesRecipientEditModal({
                        label: curLabel,
                        note: curNote
                    });
                    if (!edit) return;

                    const newLabel = edit.label;
                    const newNote = edit.note;

                    btn.disabled = true;
                    try {
                        await updatePqRecipient(s.token, recipient.recipient_device_id, {
                            label: String(newLabel),
                            note: String(newNote)
                        });
                        toast("ok", sharesT("sharesmgr.recipient_updated", null, "Recipient updated."));
                        await loadShares();
                    } catch (err) {
                        toast("err", String(err && err.message ? err.message : err));
                    } finally {
                        btn.disabled = false;
                    }
                }));
            }

            if (inviteAbs) {
                wrap.appendChild(makeActionButton(sharesT("sharesmgr.copy_invite", null, "Copy invite"), "btn", async () => {
                    const ok = await copyText(inviteAbs);
                    toast(ok ? "ok" : "err", ok ? sharesT("sharesmgr.copied_invite", null, "Copied invite link.") : sharesT("sharesmgr.copy_failed", null, "Copy failed."));
                }));
            }

            wrap.appendChild(makeActionButton(sharesT("sharesmgr.revoke", null, "Revoke"), "btn btnDanger", async (e) => {
                const btn = e.currentTarget;
                btn.disabled = true;
                try {
                    await revokeShare(s.token);
                    toast("ok", sharesT("sharesmgr.revoked", null, "Revoked."));
                    await loadShares();
                } catch (err) {
                    toast("err", String(err && err.message ? err.message : err));
                } finally {
                    btn.disabled = false;
                }
            }));

            act.appendChild(wrap);
            tr.appendChild(act);

            tbodyPq.appendChild(tr);
        }
    }

    function render() {
        const filteredAll = applySort(applyFilters(shares));
        const groups = splitShares(filteredAll);

        const hasWorkspaceShares = shares.some(isWorkspaceShare);

        if (workspaceCard) {
            workspaceCard.classList.toggle("hidden", !hasWorkspaceShares);
        }

        const showTok = !!showToken?.checked;
        if (thTokenStandard) thTokenStandard.classList.toggle("hidden", !showTok);
        if (thTokenWorkspace) thTokenWorkspace.classList.toggle("hidden", !showTok);
        if (thTokenPq) thTokenPq.classList.toggle("hidden", !showTok);

        if (countPillStandard) countPillStandard.textContent = String(groups.standard.length);
        if (countPillWorkspace) countPillWorkspace.textContent = String(groups.workspace.length);
        if (countPillPq) countPillPq.textContent = String(groups.pq.length);

        renderStandardRows(groups.standard, showTok);
        renderWorkspaceRows(groups.workspace, showTok);
        renderPqRows(groups.pq, showTok);

        if (btnRevokeExpired) {
            const nExp = expiredShares(shares).length;
            btnRevokeExpired.textContent = nExp ? sharesT("sharesmgr.revoke_expired_count", { count: nExp }, "Revoke expired ({count})") : sharesT("sharesmgr.revoke_expired", null, "Revoke expired");
            btnRevokeExpired.disabled = (nExp === 0);
        }

        if (lastLoadedAt && statusLine) {
            const ageSec = Math.round((Date.now() - lastLoadedAt) / 1000);
            statusLine.textContent =
                sharesT("sharesmgr.status_summary", { shown: groups.standard.length + groups.workspace.length + groups.pq.length, total: shares.length, standard: groups.standard.length, workspace: groups.workspace.length, pq: groups.pq.length, age: ageSec }, "Showing {shown}/{total}. My shares {standard}. Workspace shares {workspace}. PQ shares {pq}. Last refresh {age}s ago.");
        }
    }

    if (btnRevokeExpired) btnRevokeExpired.classList.add("btnDanger");

    if (btnRefresh) btnRefresh.onclick = () => loadShares();
    if (btnRevokeExpired) btnRevokeExpired.onclick = () => revokeExpired();

    if (btnClear) btnClear.onclick = () => {
        if (q) q.value = "";
        if (state) state.value = "all";
        if (sort) sort.value = "created_desc";
        if (showToken) showToken.checked = false;
        render();
    };

    if (q) q.oninput = () => render();
    if (state) state.onchange = () => render();
    if (sort) sort.onchange = () => render();
    if (showToken) showToken.onchange = () => render();

    initSectionToggles();
    loadVersion();
    loadShares().catch(() => {
        if (statusLine) statusLine.textContent = sharesT("sharesmgr.failed_network", null, "Failed to load (network error).");
        render();
    });
})();