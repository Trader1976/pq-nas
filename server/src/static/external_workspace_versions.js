window.ExternalWorkspaceVersions = window.ExternalWorkspaceVersions || {};

(() => {
    "use strict";

    if (window.ExternalWorkspaceVersions.__ready) return;

    const api = window.ExternalWorkspaceVersions;

    const state = {
        item: null,
        ctx: null,
        relPath: "",
        versions: [],
        loading: false,
        restoringVersionId: "",
        closeAfterRestore: false
    };

    let rootEl = null;
    let panelEl = null;
    let titleEl = null;
    let pathEl = null;
    let statusEl = null;
    let bodyEl = null;
    let refreshBtn = null;
    let closeBtn = null;
    let closeAfterRestoreCb = null;

    function injectCss() {
        if (document.getElementById("externalWorkspaceVersionsCss")) return;

        const style = document.createElement("style");
        style.id = "externalWorkspaceVersionsCss";
        style.textContent = `
.externalVersionsRoot{
    position:fixed;
    inset:0;
    display:none;
    align-items:center;
    justify-content:center;
    padding:20px;
    background:rgba(0,0,0,.48);
    z-index:7000;
}
.externalVersionsRoot.show{display:flex;}
.externalVersionsPanel{
    width:min(920px,calc(100vw - 32px));
    max-height:calc(100vh - 32px);
    display:flex;
    flex-direction:column;
    overflow:hidden;
    border-radius:18px;
    border:1px solid rgba(255,255,255,.14);
    background:var(--card-bg,var(--panel,#171717));
    color:var(--fg,#f3f3f3);
    box-shadow:0 22px 70px rgba(0,0,0,.5);
}
.externalVersionsHead{
    display:flex;
    align-items:flex-start;
    justify-content:space-between;
    gap:12px;
    padding:16px 18px 12px;
    border-bottom:1px solid rgba(255,255,255,.10);
}
.externalVersionsHeadLeft{
    min-width:0;
    flex:1;
}
.externalVersionsHeadRight{
    display:flex;
    align-items:center;
    gap:8px;
    flex-wrap:wrap;
}
.externalVersionsTitle{
    font-size:18px;
    font-weight:800;
    line-height:1.2;
}
.externalVersionsPath{
    margin-top:6px;
    opacity:.82;
    word-break:break-all;
    font-size:12px;
}
.externalVersionsStatus{
    padding:10px 18px;
    font-size:13px;
    opacity:.92;
    border-bottom:1px solid rgba(255,255,255,.07);
}
.externalVersionsStatus.warn{color:var(--warn,#f0b429);}
.externalVersionsStatus.err{color:var(--err,#ff6b6b);}
.externalVersionsStatus.ok{color:var(--ok,#59d185);}
.externalVersionsBody{
    padding:14px 18px 18px;
    overflow:auto;
}
.externalVersionsEmpty{
    padding:18px;
    border-radius:14px;
    background:rgba(255,255,255,.05);
    opacity:.94;
}
.externalVersionsEmpty.err{color:var(--err,#ff6b6b);}
.externalVersionsList{
    display:flex;
    flex-direction:column;
    gap:12px;
}
.externalVersionsRow{
    border:1px solid rgba(255,255,255,.12);
    border-radius:16px;
    padding:14px;
    background:rgba(255,255,255,.04);
}
.externalVersionsRow.deleted{
    border-color:rgba(240,180,41,.38);
}
.externalVersionsRowTop{
    display:flex;
    align-items:flex-start;
    justify-content:space-between;
    gap:14px;
}
.externalVersionsRowLeft{
    min-width:0;
    flex:1;
}
.externalVersionsKind{
    font-weight:800;
    line-height:1.2;
}
.externalVersionsMeta{
    margin-top:6px;
    font-size:13px;
    opacity:.82;
    word-break:break-word;
}
.externalVersionsActions{
    display:flex;
    gap:8px;
    flex-wrap:wrap;
}
.externalVersionsRowBottom{
    margin-top:10px;
    display:flex;
    flex-direction:column;
    gap:4px;
}
.externalVersionsMini{
    font-size:12px;
    opacity:.78;
    word-break:break-all;
}
.externalVersionsCloseAfter{
    display:inline-flex;
    align-items:center;
    gap:8px;
    font-size:12px;
    opacity:.9;
    white-space:nowrap;
}
.externalVersionsCloseAfter input{margin:0;}
@media (max-width:760px){
    .externalVersionsRoot{padding:10px;}
    .externalVersionsPanel{
        width:100%;
        max-height:calc(100vh - 20px);
    }
    .externalVersionsHead{
        flex-direction:column;
    }
    .externalVersionsRowTop{
        flex-direction:column;
    }
    .externalVersionsActions{
        width:100%;
    }
}
`;
        document.head.appendChild(style);
    }

    function normalizeRelPath(p) {
        return String(p || "")
            .replace(/\\/g, "/")
            .replace(/^\/+/, "")
            .replace(/\/+/g, "/")
            .replace(/\/+$/, "");
    }

    function fmtSize(n) {
        const v = Number(n || 0);
        if (!Number.isFinite(v) || v <= 0) return "0 B";
        const units = ["B", "KB", "MB", "GB", "TB"];
        let x = v;
        let i = 0;
        while (x >= 1024 && i < units.length - 1) {
            x /= 1024;
            i++;
        }
        return `${x >= 10 || i === 0 ? x.toFixed(0) : x.toFixed(1)} ${units[i]}`;
    }

    function actorDisplay(row) {
        return String(
            row.actor_display ||
            row.actor_name_snapshot ||
            row.actor_fp ||
            "Unknown"
        );
    }

    function kindLabel(row) {
        if (row && row.is_deleted_event) return "Deleted file snapshot";
        if (row && row.event_kind === "overwrite_preserve") return "Before overwrite";
        if (row && row.event_kind === "delete_preserve") return "Before delete";
        if (row && row.event_kind === "restore_preserve") return "Before restore";
        return String((row && row.event_kind) || "Version");
    }

    function detailLine(row) {
        const parts = [];
        if (row && row.created_at) parts.push(row.created_at);
        else if (row && row.created_epoch) parts.push(String(row.created_epoch));
        parts.push(actorDisplay(row || {}));
        parts.push(fmtSize(row && row.bytes || 0));
        return parts.join(" • ");
    }

    function shortSha(sha) {
        const s = String(sha || "");
        if (!s) return "";
        if (s.length <= 32) return s;
        return `${s.slice(0, 16)}…${s.slice(-12)}`;
    }

    async function copyText(text) {
        const s = String(text || "");
        if (!s) return false;

        try {
            if (navigator.clipboard && window.isSecureContext) {
                await navigator.clipboard.writeText(s);
                return true;
            }
        } catch (_) {}

        try {
            const ta = document.createElement("textarea");
            ta.value = s;
            ta.setAttribute("readonly", "readonly");
            ta.style.position = "fixed";
            ta.style.left = "-9999px";
            document.body.appendChild(ta);
            ta.select();
            const ok = document.execCommand("copy");
            ta.remove();
            return !!ok;
        } catch (_) {
            return false;
        }
    }

    function setGlobalStatus(text, kind) {
        const ctx = state.ctx || {};
        if (typeof ctx.setStatus === "function") {
            ctx.setStatus(text || "", kind === "err" ? "bad" : kind);
        }
    }

    function workspaceId() {
        const ctx = state.ctx || {};
        return String(ctx.workspaceId || "").trim();
    }

    function buildListUrl(relPath, limit = 100) {
        const qs = new URLSearchParams();
        qs.set("workspace_id", workspaceId());
        qs.set("path", normalizeRelPath(relPath));
        qs.set("limit", String(limit));
        return `/api/v4/workspaces/files/versions/list?${qs.toString()}`;
    }

    function buildRestoreBody(relPath, versionId) {
        return {
            workspace_id: workspaceId(),
            path: normalizeRelPath(relPath),
            version_id: String(versionId || "")
        };
    }

    function ensureDom() {
        if (rootEl) return;

        injectCss();

        rootEl = document.createElement("div");
        rootEl.className = "externalVersionsRoot";
        rootEl.setAttribute("aria-hidden", "true");

        panelEl = document.createElement("div");
        panelEl.className = "externalVersionsPanel";
        panelEl.setAttribute("role", "dialog");
        panelEl.setAttribute("aria-modal", "true");
        panelEl.setAttribute("aria-labelledby", "externalVersionsTitle");

        const headEl = document.createElement("div");
        headEl.className = "externalVersionsHead";

        const headLeftEl = document.createElement("div");
        headLeftEl.className = "externalVersionsHeadLeft";

        titleEl = document.createElement("div");
        titleEl.className = "externalVersionsTitle";
        titleEl.id = "externalVersionsTitle";
        titleEl.textContent = "File versions";

        pathEl = document.createElement("div");
        pathEl.className = "externalVersionsPath mono";

        headLeftEl.appendChild(titleEl);
        headLeftEl.appendChild(pathEl);

        const headRightEl = document.createElement("div");
        headRightEl.className = "externalVersionsHeadRight";

        const closeAfterWrap = document.createElement("label");
        closeAfterWrap.className = "externalVersionsCloseAfter";

        closeAfterRestoreCb = document.createElement("input");
        closeAfterRestoreCb.type = "checkbox";
        closeAfterRestoreCb.checked = !!state.closeAfterRestore;
        closeAfterRestoreCb.addEventListener("change", () => {
            state.closeAfterRestore = !!closeAfterRestoreCb.checked;
        });

        const closeAfterTxt = document.createElement("span");
        closeAfterTxt.textContent = "Close after restore";

        closeAfterWrap.appendChild(closeAfterRestoreCb);
        closeAfterWrap.appendChild(closeAfterTxt);

        refreshBtn = document.createElement("button");
        refreshBtn.type = "button";
        refreshBtn.className = "btn secondary";
        refreshBtn.textContent = "Refresh";
        refreshBtn.addEventListener("click", () => {
            loadVersions().catch((e) => {
                setModalError(String(e && e.message ? e.message : e));
            });
        });

        closeBtn = document.createElement("button");
        closeBtn.type = "button";
        closeBtn.className = "btn secondary";
        closeBtn.textContent = "Close";
        closeBtn.addEventListener("click", close);

        headRightEl.appendChild(closeAfterWrap);
        headRightEl.appendChild(refreshBtn);
        headRightEl.appendChild(closeBtn);

        headEl.appendChild(headLeftEl);
        headEl.appendChild(headRightEl);

        statusEl = document.createElement("div");
        statusEl.className = "externalVersionsStatus";

        bodyEl = document.createElement("div");
        bodyEl.className = "externalVersionsBody";

        panelEl.appendChild(headEl);
        panelEl.appendChild(statusEl);
        panelEl.appendChild(bodyEl);

        rootEl.appendChild(panelEl);
        document.body.appendChild(rootEl);

        rootEl.addEventListener("click", (e) => {
            if (e.target === rootEl) close();
        });

        document.addEventListener("keydown", (e) => {
            if (!rootEl || !rootEl.classList.contains("show")) return;
            if (e.key === "Escape") {
                e.preventDefault();
                close();
            }
        });
    }

    function show() {
        ensureDom();
        rootEl.classList.add("show");
        rootEl.setAttribute("aria-hidden", "false");
    }

    function close() {
        if (!rootEl) return;
        rootEl.classList.remove("show");
        rootEl.setAttribute("aria-hidden", "true");
        state.restoringVersionId = "";
    }

    function setModalStatus(text, kind = "") {
        if (!statusEl) return;
        statusEl.className = `externalVersionsStatus${kind ? " " + kind : ""}`;
        statusEl.textContent = text || "";
    }

    function setModalLoading(text) {
        if (!bodyEl) return;
        setModalStatus(text || "Loading versions…", "warn");
        bodyEl.innerHTML = "";
        const div = document.createElement("div");
        div.className = "externalVersionsEmpty";
        div.textContent = text || "Loading versions…";
        bodyEl.appendChild(div);
    }

    function setModalError(text) {
        if (!bodyEl) return;
        setModalStatus(text || "Failed to load versions", "err");
        bodyEl.innerHTML = "";
        const div = document.createElement("div");
        div.className = "externalVersionsEmpty err";
        div.textContent = text || "Failed to load versions";
        bodyEl.appendChild(div);
    }

    async function fetchVersions() {
        const r = await fetch(buildListUrl(state.relPath, 100), {
            method: "GET",
            credentials: "include",
            cache: "no-store",
            headers: { "Accept": "application/json" }
        });

        const j = await r.json().catch(() => null);
        if (!r.ok || !j || !j.ok) {
            const msg = j && (j.message || j.error)
                ? `${j.error || ""} ${j.message || ""}`.trim()
                : `HTTP ${r.status}`;
            throw new Error(msg || "failed to load versions");
        }

        return Array.isArray(j.versions) ? j.versions : [];
    }

    function renderVersions() {
        if (!bodyEl) return;
        bodyEl.innerHTML = "";

        if (!state.versions.length) {
            setModalStatus("No preserved versions for this file.");
            const div = document.createElement("div");
            div.className = "externalVersionsEmpty";
            div.textContent = "No preserved versions for this file yet.";
            bodyEl.appendChild(div);
            return;
        }

        setModalStatus(`${state.versions.length} version(s)`);

        const listEl = document.createElement("div");
        listEl.className = "externalVersionsList";

        for (const row of state.versions) {
            listEl.appendChild(renderRow(row));
        }

        bodyEl.appendChild(listEl);
    }

    function renderRow(row) {
        const rowEl = document.createElement("div");
        rowEl.className = "externalVersionsRow" + (row && row.is_deleted_event ? " deleted" : "");

        const topEl = document.createElement("div");
        topEl.className = "externalVersionsRowTop";

        const leftEl = document.createElement("div");
        leftEl.className = "externalVersionsRowLeft";

        const kindEl = document.createElement("div");
        kindEl.className = "externalVersionsKind";
        kindEl.textContent = kindLabel(row);

        const metaEl = document.createElement("div");
        metaEl.className = "externalVersionsMeta";
        metaEl.textContent = detailLine(row);

        leftEl.appendChild(kindEl);
        leftEl.appendChild(metaEl);

        const actionsEl = document.createElement("div");
        actionsEl.className = "externalVersionsActions";

        const restoreBtn = document.createElement("button");
        restoreBtn.type = "button";
        restoreBtn.className = "btn";
        restoreBtn.textContent = state.restoringVersionId === row.version_id ? "Restoring…" : "Restore";
        restoreBtn.disabled = !!state.restoringVersionId || !(state.ctx && state.ctx.canWrite);
        restoreBtn.title = (state.ctx && state.ctx.canWrite)
            ? "Restore this preserved version"
            : "Restore requires editor access";
        restoreBtn.addEventListener("click", () => {
            restoreVersion(row).catch((e) => {
                setModalStatus(String(e && e.message ? e.message : e), "err");
            });
        });

        const copyBtn = document.createElement("button");
        copyBtn.type = "button";
        copyBtn.className = "btn secondary";
        copyBtn.textContent = "Copy SHA";
        copyBtn.disabled = !(row && row.sha256_hex);
        copyBtn.addEventListener("click", async () => {
            if (!row || !row.sha256_hex) return;
            const ok = await copyText(row.sha256_hex);
            copyBtn.textContent = ok ? "Copied" : "Copy failed";
            setTimeout(() => { copyBtn.textContent = "Copy SHA"; }, 1000);
        });

        actionsEl.appendChild(restoreBtn);
        actionsEl.appendChild(copyBtn);

        topEl.appendChild(leftEl);
        topEl.appendChild(actionsEl);

        const bottomEl = document.createElement("div");
        bottomEl.className = "externalVersionsRowBottom";

        const idEl = document.createElement("div");
        idEl.className = "externalVersionsMini mono";
        idEl.textContent = `version_id: ${(row && row.version_id) || ""}`;

        const shaEl = document.createElement("div");
        shaEl.className = "externalVersionsMini mono";
        shaEl.textContent = `sha256: ${shortSha((row && row.sha256_hex) || "")}`;

        bottomEl.appendChild(idEl);
        bottomEl.appendChild(shaEl);

        rowEl.appendChild(topEl);
        rowEl.appendChild(bottomEl);

        return rowEl;
    }

    async function loadVersions() {
        state.loading = true;
        setModalLoading("Loading versions…");

        try {
            state.versions = await fetchVersions();
            renderVersions();
        } catch (e) {
            setModalError(String(e && e.message ? e.message : e));
        } finally {
            state.loading = false;
        }
    }

    async function restoreVersion(row) {
        if (!(state.ctx && state.ctx.canWrite)) {
            setModalStatus("Restore requires editor access.", "err");
            return;
        }

        const label = kindLabel(row);
        const ok = window.confirm(
            `Restore this version?\n\n` +
            `Path: /${state.relPath}\n` +
            `Kind: ${label}\n` +
            `Created: ${(row && row.created_at) || ""}`
        );
        if (!ok) return;

        state.restoringVersionId = row.version_id;
        renderVersions();
        setModalStatus("Restoring version…", "warn");
        setGlobalStatus(`Restoring version: /${state.relPath}`, "warn");

        try {
            const r = await fetch("/api/v4/workspaces/files/restore_version", {
                method: "POST",
                credentials: "include",
                cache: "no-store",
                headers: {
                    "Content-Type": "application/json",
                    "Accept": "application/json"
                },
                body: JSON.stringify(buildRestoreBody(state.relPath, row.version_id))
            });

            const j = await r.json().catch(() => null);
            if (!r.ok || !j || !j.ok) {
                const msg = j && (j.message || j.error)
                    ? `${j.error || ""} ${j.message || ""}`.trim()
                    : `HTTP ${r.status}`;
                throw new Error(msg || "restore failed");
            }

            if (state.ctx && typeof state.ctx.reload === "function") {
                await state.ctx.reload();
            }

            if (state.closeAfterRestore) {
                setGlobalStatus(`Restored version: /${state.relPath}`, "good");
                close();
                return;
            }
        } finally {
            state.restoringVersionId = "";
        }

        await loadVersions();
        renderVersions();
        setModalStatus("Version restored. Current file replaced successfully.", "ok");
        setGlobalStatus(`Restored version: /${state.relPath}`, "good");
    }

    api.canOpenFor = function canOpenFor(item) {
        return !!item && !item.isDir && String(item.type || "file") === "file";
    };

    api.open = function open(item, ctx) {
        if (!api.canOpenFor(item)) {
            if (ctx && typeof ctx.setStatus === "function") {
                ctx.setStatus("Versions are available for files only.", "bad");
            }
            return;
        }

        ensureDom();

        state.item = item;
        state.ctx = ctx || {};
        state.relPath = normalizeRelPath(item.rel || "");
        state.versions = [];
        state.restoringVersionId = "";

        titleEl.textContent = "File versions";
        pathEl.textContent = "/" + state.relPath;

        if (closeAfterRestoreCb) {
            closeAfterRestoreCb.checked = !!state.closeAfterRestore;
        }

        show();
        loadVersions().catch((e) => {
            setModalError(String(e && e.message ? e.message : e));
        });
    };

    api.close = close;
    api.__ready = true;
})();
