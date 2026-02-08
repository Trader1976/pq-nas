(() => {
    "use strict";

    const $ = (id) => document.getElementById(id);
    const appVersionEl = $("appVersion");

    const btnRefresh = $("btnRefresh");
    const btnRevokeExpired = $("btnRevokeExpired");
    const btnClear = $("btnClear");

    const toastArea = $("toastArea");

    const q = $("q");
    const state = $("state");
    const sort = $("sort");
    const showToken = $("showToken");
    const thToken = $("thToken");

    const tbody = $("tbody");
    const countPill = $("countPill");
    const statusLine = $("statusLine");

    let shares = []; // raw shares from server
    let lastLoadedAt = 0;

    function nowMs(){ return Date.now(); }

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
        if (statusLine) statusLine.textContent = `Loaded ${shares.length} shares.`;
        render();
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
            // Revoke sequentially (safer for server + simpler)
            for (const s of exp) {
                try {
                    const { r, j } = await apiJson("POST", "/api/v4/shares/revoke", { token: s.token });
                    if (r.ok && j && j.ok) okCount++;
                    else failCount++;
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

        let out = list;

        if (qq) {
            out = out.filter(s => {
                const a = (s.path || "").toLowerCase();
                const b = (s.token || "").toLowerCase();
                return a.includes(qq) || b.includes(qq);
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

    function render() {
        const filtered = applySort(applyFilters(shares));
        if (countPill) countPill.textContent = String(filtered.length);

        const showTok = !!showToken?.checked;
        if (thToken) thToken.classList.toggle("hidden", !showTok);

        if (!tbody) return;
        tbody.innerHTML = "";

        if (!filtered.length) {
            const tr = document.createElement("tr");
            const colCount = showTok ? 8 : 7;
            const cell = document.createElement("td");
            cell.colSpan = colCount;
            cell.className = "empty";
            cell.textContent = shares.length ? "No matches." : "No shares yet.";
            tr.appendChild(cell);
            tbody.appendChild(tr);

            if (lastLoadedAt && statusLine) {
                const ageSec = Math.round((Date.now() - lastLoadedAt) / 1000);
                statusLine.textContent = `Showing 0/${shares.length}. Last refresh ${ageSec}s ago.`;
            }
            return;
        }

        for (const s of filtered) {
            const tr = document.createElement("tr");

            // Path + state badge
            const expired = isExpired(s);
            const badge = expired
                ? `<span class="badge badgeDanger">expired</span>`
                : (s.expires_at
                    ? `<span class="badge">active</span>`
                    : `<span class="badge badgeDim">no expiry</span>`);

            tr.appendChild(
                tdHtml(
                    `${escapeHtml(s.path || "")}<div style="margin-top:6px">${badge}</div>`,
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
                tr.appendChild(td((s.token || ""), "colToken"));
            }

            /* ---------- Actions ---------- */

            const act = document.createElement("td");
            act.className = "colAct";

            const wrap = document.createElement("div");
            wrap.className = "actions";

            const btnCopy = document.createElement("button");
            btnCopy.className = "btn";
            btnCopy.textContent = "Copy link";
            btnCopy.onclick = async () => {
                const ok = await copyText(urlAbs);
                toast(ok ? "ok" : "err", ok ? "Copied link." : "Copy failed.");
            };

            const btnRevoke = document.createElement("button");
            btnRevoke.className = "btn btnDanger";
            btnRevoke.textContent = "Revoke";
            btnRevoke.onclick = async () => {
                btnRevoke.disabled = true;
                try {
                    const { r, j } = await apiJson(
                        "POST",
                        "/api/v4/shares/revoke",
                        { token: s.token }
                    );
                    if (r.ok && j && j.ok) {
                        toast("ok", "Revoked.");
                        await loadShares();
                    } else {
                        const msg =
                            (j && j.message)
                                ? j.message
                                : `revoke failed (${r.status})`;
                        toast("err", msg);
                    }
                } finally {
                    btnRevoke.disabled = false;
                }
            };

            wrap.appendChild(btnCopy);
            wrap.appendChild(btnRevoke);
            act.appendChild(wrap);

            tr.appendChild(act);

            tbody.appendChild(tr);
        }

        // Update bulk revoke button label + enabled state
        if (btnRevokeExpired) {
            const nExp = expiredShares(shares).length;
            btnRevokeExpired.textContent = nExp
                ? `Revoke expired (${nExp})`
                : "Revoke expired";
            btnRevokeExpired.disabled = (nExp === 0);
        }

        if (lastLoadedAt && statusLine) {
            const ageSec = Math.round((Date.now() - lastLoadedAt) / 1000);
            statusLine.textContent = `Showing ${filtered.length}/${shares.length}. Last refresh ${ageSec}s ago.`;
        }

    }

    function escapeHtml(s) {
        return String(s).replace(/[&<>"']/g, (c) => ({
            "&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"
        }[c]));
    }

    function escapeAttr(s) {
        return escapeHtml(s).replace(/`/g, "&#96;");
    }

// Events

// style bulk revoke button as danger
    if (btnRevokeExpired) btnRevokeExpired.classList.add("btnDanger");

    if (btnRefresh) btnRefresh.onclick = () => loadShares();

    if (btnRevokeExpired) btnRevokeExpired.onclick = () => revokeExpired();

    if (btnClear) btnClear.onclick = () => {
        if (q) q.value = "";
        if (state) state.value = "all";
        if (sort) sort.value = "created_desc";
        render();
    };

    if (q) q.oninput = () => render();
    if (state) state.onchange = () => render();
    if (sort) sort.onchange = () => render();

    if (showToken) showToken.onchange = () => render();

// Boot
    loadVersion();
    loadShares().catch(() => {
        if (statusLine) statusLine.textContent = "Failed to load (network error).";
        render();
    });
})();