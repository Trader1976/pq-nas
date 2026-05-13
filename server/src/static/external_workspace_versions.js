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

/* Detached compare window: no dark modal blanket, sharp classic window. */
.externalCompareRoot{
    display:block !important;
    background:transparent !important;
    pointer-events:none !important;
    padding:0 !important;
}
.externalComparePanel{
    position:absolute !important;
    left:50%;
    top:72px;
    transform:translateX(-50%);
    width:min(1220px,calc(100vw - 32px));
    height:min(820px,calc(100vh - 96px));
    max-height:calc(100vh - 24px) !important;
    border-radius:0 !important;
    resize:both;
    pointer-events:auto !important;
    background:#f0f0f0 !important;
    color:#111 !important;
    box-shadow:0 22px 70px rgba(0,0,0,.38);
}
.externalComparePanel .externalVersionsHead{
    cursor:move;
    background:#f0f0f0 !important;
    color:#111 !important;
}
.externalComparePanel .externalVersionsHeadRight,
.externalComparePanel button,
.externalComparePanel input,
.externalComparePanel label{
    cursor:default;
}
.externalComparePanel .externalVersionsStatus{
    background:#f4f4f4 !important;
    color:#111 !important;
}
.externalComparePanel .externalVersionsStatus.ok{
    color:#21783a !important;
}
.externalComparePanel .externalVersionsBody{
    background:#ffffff !important;
}
.externalComparePane{
    background:#ffffff !important;
    color:#111 !important;
}
.externalComparePaneHeader{
    background:#e8e8e8 !important;
    color:#111 !important;
}
.externalCompareSkip{
    background:#eeeeee !important;
}
.externalCompareLineDel{
    background:#ffdede !important;
}
.externalCompareLineIns{
    background:#ddf4e5 !important;
}
.externalCompareMarkDel{
    color:#b00020 !important;
}
.externalCompareMarkIns{
    color:#107c41 !important;
}

.externalCompareResizeHandle{
    position:absolute;
    right:0;
    bottom:0;
    width:18px;
    height:18px;
    cursor:nwse-resize;
    z-index:5;
}
.externalCompareResizeHandle::before{
    content:"";
    position:absolute;
    right:4px;
    bottom:4px;
    width:10px;
    height:10px;
    border-right:2px solid rgba(0,0,0,.45);
    border-bottom:2px solid rgba(0,0,0,.45);
}
.externalComparePanel{
    min-width:620px;
    min-height:420px;
}
@media (max-width:760px){
    .externalComparePanel{
        left:12px !important;
        top:12px !important;
        transform:none !important;
        width:calc(100vw - 24px) !important;
        height:calc(100vh - 24px) !important;
    }
}

.externalVersionsFlagSummary{
    display:inline-flex;
    align-items:center;
    width:max-content;
    max-width:100%;
    margin:6px 0 4px;
    padding:4px 9px;
    border:1px solid rgba(180,120,0,.55);
    border-radius:999px;
    background:rgba(255,190,0,.20);
    color:var(--fg,#f4f4f4);
    font-weight:850;
}
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

    const TEXT_EXTS = new Set([
        "txt", "md", "log", "json", "html", "htm", "css", "js", "ts",
        "c", "cc", "cpp", "h", "hpp", "py", "sh", "yml", "yaml",
        "ini", "conf", "csv", "xml", "sql", "toml"
    ]);

    function canComparePath(relPath) {
        const s = String(relPath || "").toLowerCase();
        const i = s.lastIndexOf(".");
        if (i < 0) return false;
        return TEXT_EXTS.has(s.slice(i + 1));
    }

    function flagSummary(row) {
        const flags = Array.isArray(row && row.flags) ? row.flags : [];
        const count = Number((row && row.flag_count) || flags.length || 0);
        if (!count) return "";

        const names = flags
            .map((f) => String(f.actor_display || f.actor_name_snapshot || f.actor_fp || "").trim())
            .filter(Boolean);

        if (names.length === 1) return `⭐ ${names[0]} flagged this version`;
        if (names.length === 2) return `⭐ ${names[0]} and ${names[1]} flagged this version`;
        if (names.length > 2) return `⭐ ${names[0]}, ${names[1]} and ${names.length - 2} more flagged this version`;

        return `⭐ Flagged by ${count} user${count === 1 ? "" : "s"}`;
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

    function buildDownloadUrl(relPath, versionId) {
        const qs = new URLSearchParams();
        qs.set("workspace_id", workspaceId());
        qs.set("path", normalizeRelPath(relPath));
        qs.set("version_id", String(versionId || ""));
        return `/api/v4/workspaces/files/versions/download?${qs.toString()}`;
    }

    function buildFlagUrl(flaggedByMe) {
        return flaggedByMe
            ? `/api/v4/workspaces/files/versions/unflag`
            : `/api/v4/workspaces/files/versions/flag`;
    }

    function buildFlagBody(relPath, versionId) {
        return {
            workspace_id: workspaceId(),
            path: normalizeRelPath(relPath),
            version_id: String(versionId || ""),
            note: ""
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

    async function fetchJson(url) {
        const r = await fetch(url, {
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
            throw new Error(msg || "request failed");
        }

        return j;
    }

    function buildReadCurrentTextUrl(relPath) {
        const qs = new URLSearchParams();
        qs.set("workspace_id", workspaceId());
        qs.set("path", normalizeRelPath(relPath));
        return `/api/v4/workspaces/files/read_text?${qs.toString()}`;
    }

    function buildReadVersionTextUrl(relPath, versionId) {
        const qs = new URLSearchParams();
        qs.set("workspace_id", workspaceId());
        qs.set("path", normalizeRelPath(relPath));
        qs.set("version_id", String(versionId || ""));
        return `/api/v4/workspaces/files/versions/read_text?${qs.toString()}`;
    }

    async function openCompare(row) {
        if (!canComparePath(state.relPath)) {
            setModalStatus("Compare is available for text-based files.", "err");
            return;
        }

        setModalStatus("Loading comparison…", "warn");

        try {
            const [oldJ, curJ] = await Promise.all([
                fetchJson(buildReadVersionTextUrl(state.relPath, row.version_id)),
                fetchJson(buildReadCurrentTextUrl(state.relPath))
            ]);

            openSimpleCompareWindow({
                path: state.relPath,
                oldTitle: `Selected version • ${oldJ.created_at || row.created_at || ""}`,
                newTitle: "Current file",
                oldText: String(oldJ.text || ""),
                newText: String(curJ.text || "")
            });

            setModalStatus("Comparison opened.", "ok");
        } catch (e) {
            setModalStatus(String(e && e.message ? e.message : e), "err");
        }
    }

    function splitLines(text) {
        return String(text || "").split("\n");
    }

    function buildDiffRows(oldText, newText) {
        const oldLines = splitLines(oldText);
        const newLines = splitLines(newText);
        const m = oldLines.length;
        const n = newLines.length;

        if (m * n > 2000000) {
            return buildFallbackDiffRows(oldLines, newLines);
        }

        const dp = new Array(m + 1);
        for (let i = 0; i <= m; i++) {
            dp[i] = new Uint32Array(n + 1);
        }

        for (let i = m - 1; i >= 0; i--) {
            const row = dp[i];
            const next = dp[i + 1];
            for (let j = n - 1; j >= 0; j--) {
                row[j] = oldLines[i] === newLines[j]
                    ? next[j + 1] + 1
                    : Math.max(next[j], row[j + 1]);
            }
        }

        const ops = [];
        let i = 0;
        let j = 0;

        while (i < m && j < n) {
            if (oldLines[i] === newLines[j]) {
                ops.push({
                    kind: "equal",
                    leftNo: i + 1,
                    rightNo: j + 1,
                    leftText: oldLines[i],
                    rightText: newLines[j]
                });
                i++;
                j++;
            } else if (dp[i + 1][j] >= dp[i][j + 1]) {
                ops.push({
                    kind: "delete",
                    leftNo: i + 1,
                    rightNo: "",
                    leftText: oldLines[i],
                    rightText: ""
                });
                i++;
            } else {
                ops.push({
                    kind: "insert",
                    leftNo: "",
                    rightNo: j + 1,
                    leftText: "",
                    rightText: newLines[j]
                });
                j++;
            }
        }

        while (i < m) {
            ops.push({
                kind: "delete",
                leftNo: i + 1,
                rightNo: "",
                leftText: oldLines[i],
                rightText: ""
            });
            i++;
        }

        while (j < n) {
            ops.push({
                kind: "insert",
                leftNo: "",
                rightNo: j + 1,
                leftText: "",
                rightText: newLines[j]
            });
            j++;
        }

        return coalesceDiffOps(ops, false);
    }

    function buildFallbackDiffRows(oldLines, newLines) {
        const rows = [];
        const stats = { inserted: 0, deleted: 0, changed: 0 };
        const n = Math.max(oldLines.length, newLines.length);

        for (let i = 0; i < n; i++) {
            const hasLeft = i < oldLines.length;
            const hasRight = i < newLines.length;
            const leftText = hasLeft ? oldLines[i] : "";
            const rightText = hasRight ? newLines[i] : "";

            if (hasLeft && hasRight && leftText === rightText) {
                rows.push({ kind: "equal", leftNo: i + 1, rightNo: i + 1, leftText, rightText });
            } else if (hasLeft && hasRight) {
                stats.changed++;
                rows.push({ kind: "replace", leftNo: i + 1, rightNo: i + 1, leftText, rightText });
            } else if (hasLeft) {
                stats.deleted++;
                rows.push({ kind: "delete", leftNo: i + 1, rightNo: "", leftText, rightText: "" });
            } else {
                stats.inserted++;
                rows.push({ kind: "insert", leftNo: "", rightNo: i + 1, leftText: "", rightText });
            }
        }

        return { rows, stats, fallback: true };
    }

    function coalesceDiffOps(ops, fallback) {
        const rows = [];
        const stats = { inserted: 0, deleted: 0, changed: 0 };

        let i = 0;
        while (i < ops.length) {
            if (ops[i].kind === "equal") {
                rows.push(ops[i]);
                i++;
                continue;
            }

            const dels = [];
            const ins = [];

            while (i < ops.length && ops[i].kind !== "equal") {
                if (ops[i].kind === "delete") dels.push(ops[i]);
                else if (ops[i].kind === "insert") ins.push(ops[i]);
                i++;
            }

            const paired = Math.min(dels.length, ins.length);
            for (let k = 0; k < paired; k++) {
                stats.changed++;
                rows.push({
                    kind: "replace",
                    leftNo: dels[k].leftNo,
                    rightNo: ins[k].rightNo,
                    leftText: dels[k].leftText,
                    rightText: ins[k].rightText
                });
            }

            for (let k = paired; k < dels.length; k++) {
                stats.deleted++;
                rows.push(dels[k]);
            }

            for (let k = paired; k < ins.length; k++) {
                stats.inserted++;
                rows.push(ins[k]);
            }
        }

        return { rows, stats, fallback: !!fallback };
    }

    function compactUnchangedRows(rows, context = 3) {
        if (!Array.isArray(rows) || !rows.length) return [];

        const keep = new Set();

        for (let i = 0; i < rows.length; i++) {
            const k = rows[i] && rows[i].kind;
            if (k && k !== "equal" && k !== "skip") {
                for (let j = Math.max(0, i - context); j <= Math.min(rows.length - 1, i + context); j++) {
                    keep.add(j);
                }
            }
        }

        if (!keep.size) return rows;

        const out = [];
        let i = 0;

        while (i < rows.length) {
            if (keep.has(i)) {
                out.push(rows[i]);
                i++;
                continue;
            }

            let j = i;
            while (j < rows.length && !keep.has(j)) j++;

            out.push({
                kind: "skip",
                count: j - i,
                leftNo: "",
                rightNo: "",
                leftText: "",
                rightText: ""
            });

            i = j;
        }

        return out;
    }

    function openSimpleCompareWindow(opts) {
        const diff = buildDiffRows(opts.oldText || "", opts.newText || "");
        let hideUnchanged = false;
        let syncScroll = true;
        let syncing = false;

        const root = document.createElement("div");
        root.className = "externalVersionsRoot show externalCompareRoot";
        root.style.zIndex = "7100";

        const panel = document.createElement("div");
        panel.className = "externalVersionsPanel externalComparePanel";
        panel.style.width = "min(1220px, calc(100vw - 32px))";
        panel.style.maxHeight = "calc(100vh - 32px)";

        const head = document.createElement("div");
        head.className = "externalVersionsHead";

        const left = document.createElement("div");
        left.className = "externalVersionsHeadLeft";

        const title = document.createElement("div");
        title.className = "externalVersionsTitle";
        title.textContent = "Compare file version";

        const path = document.createElement("div");
        path.className = "externalVersionsPath mono";
        path.textContent = "/" + normalizeRelPath(opts.path || "");

        left.appendChild(title);
        left.appendChild(path);

        const actions = document.createElement("div");
        actions.className = "externalVersionsHeadRight";

        const syncLabel = document.createElement("label");
        syncLabel.className = "externalVersionsCloseAfter";

        const syncCb = document.createElement("input");
        syncCb.type = "checkbox";
        syncCb.checked = true;
        syncCb.addEventListener("change", () => {
            syncScroll = !!syncCb.checked;
        });

        const syncTxt = document.createElement("span");
        syncTxt.textContent = "Sync scroll";

        syncLabel.appendChild(syncCb);
        syncLabel.appendChild(syncTxt);

        const hideLabel = document.createElement("label");
        hideLabel.className = "externalVersionsCloseAfter";

        const hideCb = document.createElement("input");
        hideCb.type = "checkbox";
        hideCb.checked = false;
        hideCb.addEventListener("change", () => {
            hideUnchanged = !!hideCb.checked;
            render();
        });

        const hideTxt = document.createElement("span");
        hideTxt.textContent = "Hide unchanged";

        hideLabel.appendChild(hideCb);
        hideLabel.appendChild(hideTxt);

        const closeBtn2 = document.createElement("button");
        closeBtn2.type = "button";
        closeBtn2.className = "btn secondary";
        closeBtn2.textContent = "Close";
        closeBtn2.addEventListener("click", () => root.remove());

        actions.appendChild(syncLabel);
        actions.appendChild(hideLabel);
        actions.appendChild(closeBtn2);

        head.appendChild(left);
        head.appendChild(actions);

        const status = document.createElement("div");
        status.className = "externalVersionsStatus ok";

        const total = diff.stats.inserted + diff.stats.deleted + diff.stats.changed;
        const parts = [];
        if (diff.stats.inserted) parts.push(`+${diff.stats.inserted} added`);
        if (diff.stats.deleted) parts.push(`-${diff.stats.deleted} removed`);
        if (diff.stats.changed) parts.push(`~${diff.stats.changed} changed`);
        status.textContent = total
            ? `Loaded. ${parts.join(" • ")}${diff.fallback ? " • large-file fallback" : ""}`
            : "Loaded. No line differences found.";

        const body = document.createElement("div");
        body.className = "externalVersionsBody";
        body.style.display = "grid";
        body.style.gridTemplateColumns = "1fr 1fr";
        body.style.gap = "0";
        body.style.padding = "0";
        body.style.overflow = "hidden";
        body.style.minHeight = "520px";

        const paneA = document.createElement("div");
        const paneB = document.createElement("div");
        paneA.className = "externalComparePane";
        paneB.className = "externalComparePane";
        paneA.style.overflow = "auto";
        paneB.style.overflow = "auto";
        paneA.style.background = "#ffffff";
        paneB.style.background = "#ffffff";
        paneB.style.borderLeft = "1px solid rgba(0,0,0,.18)";

        const paneHeadA = document.createElement("div");
        const paneHeadB = document.createElement("div");
        paneHeadA.textContent = opts.oldTitle || "Selected version";
        paneHeadB.textContent = opts.newTitle || "Current file";

        for (const h of [paneHeadA, paneHeadB]) {
            h.style.position = "sticky";
            h.style.top = "0";
            h.style.zIndex = "1";
            h.style.padding = "10px 12px";
            h.style.fontWeight = "900";
            h.className = "externalComparePaneHeader";
            h.style.background = "#e8e8e8";
            h.style.borderBottom = "1px solid rgba(0,0,0,.18)";
        }

        const linesA = document.createElement("div");
        const linesB = document.createElement("div");

        paneA.appendChild(paneHeadA);
        paneA.appendChild(linesA);
        paneB.appendChild(paneHeadB);
        paneB.appendChild(linesB);

        function makeLine(row, side) {
            const isLeft = side === "left";
            const hasText = isLeft
                ? (row.leftNo !== "" && row.leftNo != null)
                : (row.rightNo !== "" && row.rightNo != null);

            const el = document.createElement("div");
            el.className = "mono";
            el.style.display = "grid";
            el.style.gridTemplateColumns = "54px 24px minmax(0, 1fr)";
            el.style.minHeight = "1.45em";
            el.style.fontSize = "12px";
            el.style.whiteSpace = "pre";
            el.style.lineHeight = "1.45";

            if (row.kind === "skip") {
                el.style.opacity = ".78";
                el.className += " externalCompareSkip";
                el.style.background = "#eeeeee";
            } else if (isLeft && (row.kind === "delete" || row.kind === "replace")) {
                el.className += " externalCompareLineDel";
                el.style.background = "#ffdede";
            } else if (!isLeft && (row.kind === "insert" || row.kind === "replace")) {
                el.className += " externalCompareLineIns";
                el.style.background = "#ddf4e5";
            } else if ((isLeft && row.kind === "insert") || (!isLeft && row.kind === "delete")) {
                el.style.opacity = ".45";
            }

            const no = document.createElement("div");
            no.style.textAlign = "right";
            no.style.padding = "0 8px";
            no.style.opacity = ".58";
            no.style.userSelect = "none";

            const mark = document.createElement("div");
            mark.style.textAlign = "center";
            mark.style.fontWeight = "950";
            mark.style.userSelect = "none";

            const code = document.createElement("div");
            code.style.padding = "0 10px";
            code.style.overflow = "visible";

            if (row.kind === "skip") {
                no.textContent = "";
                mark.textContent = "⋯";
                code.textContent = `${Number(row.count || 0)} unchanged line(s) hidden`;
                code.style.fontStyle = "italic";
            } else if (isLeft) {
                no.textContent = row.leftNo ? String(row.leftNo) : "";
                mark.textContent = (row.kind === "delete" || row.kind === "replace") ? "-" : "";
                mark.className = "externalCompareMarkDel";
                mark.style.color = "#b00020";
                code.textContent = hasText ? (String(row.leftText ?? "") || " ") : " ";
            } else {
                no.textContent = row.rightNo ? String(row.rightNo) : "";
                mark.textContent = (row.kind === "insert" || row.kind === "replace") ? "+" : "";
                mark.className = "externalCompareMarkIns";
                mark.style.color = "#107c41";
                code.textContent = hasText ? (String(row.rightText ?? "") || " ") : " ";
            }

            el.appendChild(no);
            el.appendChild(mark);
            el.appendChild(code);
            return el;
        }

        function renderPane(container, rows, side) {
            container.replaceChildren();

            const frag = document.createDocumentFragment();
            for (const row of rows) {
                frag.appendChild(makeLine(row, side));
            }
            container.appendChild(frag);
        }

        function currentRows() {
            return hideUnchanged
                ? compactUnchangedRows(diff.rows, 3)
                : diff.rows;
        }

        function render() {
            const topA = paneA.scrollTop || 0;
            const topB = paneB.scrollTop || 0;

            const rows = currentRows();
            renderPane(linesA, rows, "left");
            renderPane(linesB, rows, "right");

            paneA.scrollTop = Math.min(topA, Math.max(0, paneA.scrollHeight - paneA.clientHeight));
            paneB.scrollTop = Math.min(topB, Math.max(0, paneB.scrollHeight - paneB.clientHeight));
        }

        paneA.addEventListener("scroll", () => {
            if (!syncScroll || syncing) return;
            syncing = true;
            paneB.scrollTop = paneA.scrollTop;
            requestAnimationFrame(() => { syncing = false; });
        });

        paneB.addEventListener("scroll", () => {
            if (!syncScroll || syncing) return;
            syncing = true;
            paneA.scrollTop = paneB.scrollTop;
            requestAnimationFrame(() => { syncing = false; });
        });

        body.appendChild(paneA);
        body.appendChild(paneB);

        panel.appendChild(head);
        panel.appendChild(status);
        panel.appendChild(body);

        const resizeHandle = document.createElement("div");
        resizeHandle.className = "externalCompareResizeHandle";
        resizeHandle.title = "Resize";
        panel.appendChild(resizeHandle);

        root.appendChild(panel);
        document.body.appendChild(root);

        // Keep External Workspace marquee/selection handlers from seeing
        // drag/resize/click gestures that belong to this detached window.
        for (const evName of [
            "pointerdown", "pointerup", "mousedown", "mouseup",
            "click", "dblclick", "contextmenu", "dragstart"
        ]) {
            panel.addEventListener(evName, (e) => {
                e.stopPropagation();
            });
        }

        let interaction = "";
        let startX = 0;
        let startY = 0;
        let startLeft = 0;
        let startTop = 0;
        let startW = 0;
        let startH = 0;

        function pointerStillDown(e) {
            if (!e || typeof e.buttons !== "number") return true;
            return (e.buttons & 1) === 1;
        }

        function clampComparePanel() {
            const rect = panel.getBoundingClientRect();
            const pad = 8;
            const maxLeft = Math.max(pad, window.innerWidth - rect.width - pad);
            const maxTop = Math.max(pad, window.innerHeight - rect.height - pad);

            let leftPx = rect.left;
            let topPx = rect.top;

            leftPx = Math.max(pad, Math.min(maxLeft, leftPx));
            topPx = Math.max(pad, Math.min(maxTop, topPx));

            panel.style.transform = "none";
            panel.style.left = `${leftPx}px`;
            panel.style.top = `${topPx}px`;
        }

        function beginInteraction(kind, e) {
            const rect = panel.getBoundingClientRect();

            interaction = kind;
            startX = e.clientX;
            startY = e.clientY;
            startLeft = rect.left;
            startTop = rect.top;
            startW = rect.width;
            startH = rect.height;

            panel.style.transform = "none";
            panel.style.left = `${rect.left}px`;
            panel.style.top = `${rect.top}px`;
            panel.style.width = `${rect.width}px`;
            panel.style.height = `${rect.height}px`;
            panel.style.maxWidth = "none";

            document.body.style.userSelect = "none";
            document.body.style.cursor = kind === "resize" ? "nwse-resize" : "move";

            e.preventDefault();
            e.stopPropagation();
        }

        function endInteraction() {
            interaction = "";
            document.body.style.userSelect = "";
            document.body.style.cursor = "";
        }

        function onMove(e) {
            if (!interaction) return;

            if (!pointerStillDown(e)) {
                endInteraction();
                return;
            }

            if (interaction === "resize") {
                const rect = panel.getBoundingClientRect();
                const pad = 8;

                const maxW = Math.max(420, window.innerWidth - rect.left - pad);
                const maxH = Math.max(320, window.innerHeight - rect.top - pad);

                const nextW = Math.max(620, Math.min(maxW, startW + (e.clientX - startX)));
                const nextH = Math.max(420, Math.min(maxH, startH + (e.clientY - startY)));

                panel.style.width = `${nextW}px`;
                panel.style.height = `${nextH}px`;
                return;
            }

            if (interaction === "drag") {
                const rect = panel.getBoundingClientRect();
                const pad = 8;

                const maxLeft = Math.max(pad, window.innerWidth - rect.width - pad);
                const maxTop = Math.max(pad, window.innerHeight - rect.height - pad);

                const nextLeft = Math.max(pad, Math.min(maxLeft, startLeft + (e.clientX - startX)));
                const nextTop = Math.max(pad, Math.min(maxTop, startTop + (e.clientY - startY)));

                panel.style.left = `${nextLeft}px`;
                panel.style.top = `${nextTop}px`;
            }
        }

        head.addEventListener("pointerdown", (e) => {
            if (e.target && e.target.closest && e.target.closest("button,input,label")) return;
            beginInteraction("drag", e);
        }, true);

        resizeHandle.addEventListener("pointerdown", (e) => {
            beginInteraction("resize", e);
        }, true);

        window.addEventListener("pointermove", onMove, true);
        window.addEventListener("mousemove", onMove, true);
        window.addEventListener("pointerup", endInteraction, true);
        window.addEventListener("mouseup", endInteraction, true);
        window.addEventListener("pointercancel", endInteraction, true);
        window.addEventListener("blur", endInteraction, true);

        const oldRemove = root.remove.bind(root);
        root.remove = () => {
            endInteraction();
            window.removeEventListener("pointermove", onMove, true);
            window.removeEventListener("mousemove", onMove, true);
            window.removeEventListener("pointerup", endInteraction, true);
            window.removeEventListener("mouseup", endInteraction, true);
            window.removeEventListener("pointercancel", endInteraction, true);
            window.removeEventListener("blur", endInteraction, true);
            oldRemove();
        };

        setTimeout(clampComparePanel, 0);
        render();
    }

    async function toggleFlag(row) {
        if (!row || !row.version_id) return;

        const wasFlagged = !!row.flagged_by_me;
        setModalStatus(wasFlagged ? "Removing flag…" : "Flagging version…", "warn");

        const r = await fetch(buildFlagUrl(wasFlagged), {
            method: "POST",
            credentials: "include",
            cache: "no-store",
            headers: {
                "Content-Type": "application/json",
                "Accept": "application/json"
            },
            body: JSON.stringify(buildFlagBody(state.relPath, row.version_id))
        });

        const j = await r.json().catch(() => null);
        if (!r.ok || !j || !j.ok) {
            const msg = j && (j.message || j.error)
                ? `${j.error || ""} ${j.message || ""}`.trim()
                : `HTTP ${r.status}`;
            throw new Error(msg || "flag update failed");
        }

        await loadVersions();
        setModalStatus(wasFlagged ? "Flag removed." : "Version flagged.", "ok");
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

        const compareBtn = document.createElement("button");
        compareBtn.type = "button";
        compareBtn.className = "btn secondary";
        compareBtn.textContent = "Compare";
        compareBtn.disabled = !canComparePath(state.relPath);
        compareBtn.title = compareBtn.disabled
            ? "Compare is available for text-based files"
            : "Compare this version with the current file";
        compareBtn.addEventListener("click", () => {
            openCompare(row).catch((e) => {
                setModalStatus(String(e && e.message ? e.message : e), "err");
            });
        });

        const downloadBtn = document.createElement("button");
        downloadBtn.type = "button";
        downloadBtn.className = "btn secondary";
        downloadBtn.textContent = "Download";
        downloadBtn.title = "Download this preserved version without restoring it";
        downloadBtn.addEventListener("click", () => {
            const a = document.createElement("a");
            a.href = buildDownloadUrl(state.relPath, row.version_id);
            a.rel = "noopener";
            a.style.display = "none";
            document.body.appendChild(a);
            a.click();
            a.remove();
        });

        const flagBtn = document.createElement("button");
        flagBtn.type = "button";
        flagBtn.className = row.flagged_by_me ? "btn" : "btn secondary";
        flagBtn.textContent = row.flagged_by_me ? "⭐ Unflag" : "☆ Flag";
        flagBtn.title = row.flagged_by_me
            ? "Remove your flag from this version"
            : "Flag this version so other workspace members can see it";
        flagBtn.addEventListener("click", () => {
            toggleFlag(row).catch((e) => {
                setModalStatus(String(e && e.message ? e.message : e), "err");
            });
        });

        actionsEl.appendChild(compareBtn);
        actionsEl.appendChild(restoreBtn);
        actionsEl.appendChild(downloadBtn);
        actionsEl.appendChild(flagBtn);
        actionsEl.appendChild(copyBtn);

        topEl.appendChild(leftEl);
        topEl.appendChild(actionsEl);

        const bottomEl = document.createElement("div");
        bottomEl.className = "externalVersionsRowBottom";

        const flagText = flagSummary(row);
        if (flagText) {
            const flagEl = document.createElement("div");
            flagEl.className = "externalVersionsMini externalVersionsFlagSummary";
            flagEl.textContent = flagText;
            bottomEl.appendChild(flagEl);
        }

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
