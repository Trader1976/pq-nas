(() => {
    "use strict";

    const $ = (id) => document.getElementById(id);

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
    const pqCard = $("pqCard");
    const btnToggleStandard = $("btnToggleStandard");
    const btnTogglePq = $("btnTogglePq");

    const countPillStandard = $("countPillStandard");
    const countPillPq = $("countPillPq");

    const thTokenStandard = $("thTokenStandard");
    const thTokenPq = $("thTokenPq");

    const tbodyStandard = $("tbodyStandard");
    const tbodyPq = $("tbodyPq");

    const OPEN_STD_KEY = "sharesmgr_standard_open_v1";
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
            if (statusLine) statusLine.textContent = `Network error calling ${url}: ${msg}`;
            console.error("fetch failed:", url, e);
            throw e;
        }

        let j = null;
        try { j = await r.json(); } catch {}
        return { r, j };
    }

    async function loadVersion() {
        if (!appVersionEl) return;

        try {
            const { r, j } = await apiJson("GET", "/api/v4/apps");
            if (!r.ok || !j) return;

            const installed = j.installed || [];
            const me = installed.find(a => a.id === "sharesmgr");

            if (me && me.version) {
                appVersionEl.textContent = ` • v${me.version}`;
            }
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

    function splitShares(list) {
        const standard = [];
        const pq = [];

        for (const s of (list || [])) {
            if (isPqShare(s)) pq.push(s);
            else standard.push(s);
        }

        return { standard, pq };
    }

    function pqStateOf(s) {
        const st = String(s?.pq_state || s?.state || "").trim().toLowerCase();
        if (!st) {
            if (s?.invite_url) return "pending";
            return "active";
        }
        return st;
    }

    function pqStateBadgeHtml(s) {
        const st = pqStateOf(s);
        if (st === "active") return `<span class="badge badgeOk">active</span>`;
        if (st === "pending" || st === "pending_enrollment") return `<span class="badge badgeWarn">pending</span>`;
        if (st === "claimed") return `<span class="badge badgeOk">claimed</span>`;
        if (st === "revoked") return `<span class="badge badgeDanger">revoked</span>`;
        if (st === "expired") return `<span class="badge badgeDanger">expired</span>`;
        return `<span class="badge">${escapeHtml(st || "unknown")}</span>`;
    }

    function normalStateBadgeHtml(s) {
        if (isExpired(s)) return `<span class="badge badgeDanger">expired</span>`;
        if (s.expires_at) return `<span class="badge">active</span>`;
        return `<span class="badge badgeDim">no expiry</span>`;
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
        if (txt) txt.textContent = open ? "Hide" : "Show";

        if (persistKey) setStoredBool(persistKey, open);
    }

    function initSectionToggles() {
        const stdOpen = getStoredBool(OPEN_STD_KEY, true);
        const pqOpen = getStoredBool(OPEN_PQ_KEY, true);

        setSectionOpen(standardCard, btnToggleStandard, stdOpen, null);
        setSectionOpen(pqCard, btnTogglePq, pqOpen, null);

        btnToggleStandard?.addEventListener("click", () => {
            const nowOpen = standardCard && !standardCard.classList.contains("collapsed");
            setSectionOpen(standardCard, btnToggleStandard, !nowOpen, OPEN_STD_KEY);
        });

        btnTogglePq?.addEventListener("click", () => {
            const nowOpen = pqCard && !pqCard.classList.contains("collapsed");
            setSectionOpen(pqCard, btnTogglePq, !nowOpen, OPEN_PQ_KEY);
        });
    }

    async function loadShares() {
        if (statusLine) statusLine.textContent = "Loading shares…";

        const { r, j } = await apiJson("GET", "/api/v4/shares/list");
        if (!r.ok || !j || !j.ok || !Array.isArray(j.shares)) {
            shares = [];
            lastLoadedAt = nowMs();

            if (statusLine) {
                if (r.status === 403) {
                    statusLine.textContent = "Not allowed (403). This app needs share list access for your account.";
                } else if (r.status === 401) {
                    statusLine.textContent = "Not signed in (401). Open PQ-NAS and sign in.";
                } else {
                    statusLine.textContent = `Failed to load shares (${r.status}).`;
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
                : `revoke failed (${r.status})`;
            throw new Error(msg);
        }
    }

    async function revokeExpired() {
        const exp = expiredShares(shares);

        if (!exp.length) {
            toast("ok", "No expired shares to revoke.");
            return;
        }

        const sample = exp.slice(0, 5).map(s => s.path || "(no path)").join("\n");
        const msg =
            `Revoke ${exp.length} expired share(s)?\n\n` +
            `Examples:\n${sample}` +
            (exp.length > 5 ? `\n… +${exp.length - 5} more` : "");

        if (!confirm(msg)) return;

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

            if (okCount) toast("ok", `Revoked ${okCount} expired share(s).`);
            if (failCount) toast("err", `Failed to revoke ${failCount} expired share(s).`);

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
                const parts = [
                    s.path || "",
                    s.token || "",
                    s.url || "",
                    s.invite_url || "",
                    s.invite_id || "",
                    s.pq_state || "",
                    s.mode || "",
                    s.pq_mode || "",
                    s.kind || ""
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
            renderEmpty(tbodyStandard, shares.length ? "No normal shares match the current filter." : "No shares yet.", showTok ? 8 : 7);
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

            wrap.appendChild(makeActionButton("Copy link", "btn", async () => {
                const ok = await copyText(urlAbs);
                toast(ok ? "ok" : "err", ok ? "Copied link." : "Copy failed.");
            }));

            wrap.appendChild(makeActionButton("Revoke", "btn btnDanger", async (e) => {
                const btn = e.currentTarget;
                btn.disabled = true;
                try {
                    await revokeShare(s.token);
                    toast("ok", "Revoked.");
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

    function renderPqRows(list, showTok) {
        if (!tbodyPq) return;

        tbodyPq.innerHTML = "";

        if (!list.length) {
            renderEmpty(
                tbodyPq,
                "No PQ shares yet. When /api/v4/shares/list returns PQ metadata, they will appear here.",
                showTok ? 8 : 7
            );
            return;
        }

        for (const s of list) {
            const tr = document.createElement("tr");

            tr.appendChild(td(s.path || "", "colPath mono"));
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

            if (inviteAbs) {
                wrap.appendChild(makeActionButton("Copy invite", "btn", async () => {
                    const ok = await copyText(inviteAbs);
                    toast(ok ? "ok" : "err", ok ? "Copied invite link." : "Copy failed.");
                }));
            }

            wrap.appendChild(makeActionButton("Revoke", "btn btnDanger", async (e) => {
                const btn = e.currentTarget;
                btn.disabled = true;
                try {
                    await revokeShare(s.token);
                    toast("ok", "Revoked.");
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

        const showTok = !!showToken?.checked;
        if (thTokenStandard) thTokenStandard.classList.toggle("hidden", !showTok);
        if (thTokenPq) thTokenPq.classList.toggle("hidden", !showTok);

        if (countPillStandard) countPillStandard.textContent = String(groups.standard.length);
        if (countPillPq) countPillPq.textContent = String(groups.pq.length);

        renderStandardRows(groups.standard, showTok);
        renderPqRows(groups.pq, showTok);

        if (btnRevokeExpired) {
            const nExp = expiredShares(shares).length;
            btnRevokeExpired.textContent = nExp ? `Revoke expired (${nExp})` : "Revoke expired";
            btnRevokeExpired.disabled = (nExp === 0);
        }

        if (lastLoadedAt && statusLine) {
            const ageSec = Math.round((Date.now() - lastLoadedAt) / 1000);
            statusLine.textContent =
                `Showing ${groups.standard.length + groups.pq.length}/${shares.length}. ` +
                `My shares ${groups.standard.length}. PQ shares ${groups.pq.length}. ` +
                `Last refresh ${ageSec}s ago.`;
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
        if (statusLine) statusLine.textContent = "Failed to load (network error).";
        render();
    });
})();