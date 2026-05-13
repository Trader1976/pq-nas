window.PQNAS_FILEMGR = window.PQNAS_FILEMGR || {};

(() => {
    "use strict";

    const FM = window.PQNAS_FILEMGR;
    if (!FM || FM.fileVersionCompare) return;

    const TEXT_EXTS = new Set([
        "txt", "md", "log", "json", "html", "htm", "css", "js", "ts",
        "c", "cc", "cpp", "h", "hpp", "py", "sh", "yml", "yaml",
        "ini", "conf", "csv", "xml", "sql", "toml"
    ]);

    const state = {
        item: null,
        relPath: "",
        version: null,
        syncScroll: true,
        loading: false
    };

    let rootEl = null;
    let panelEl = null;
    let headEl = null;
    let titleEl = null;
    let pathEl = null;
    let statusEl = null;
    let leftMetaEl = null;
    let rightMetaEl = null;
    let leftArea = null;
    let rightArea = null;
    let syncCb = null;
    let scrolling = false;

    const drag = {
        active: false,
        moved: false,
        startX: 0,
        startY: 0,
        left: 0,
        top: 0
    };

    function extOf(name) {
        const s = String(name || "").toLowerCase();
        const i = s.lastIndexOf(".");
        return i >= 0 ? s.slice(i + 1) : "";
    }

    function isTextName(name) {
        return TEXT_EXTS.has(extOf(name));
    }

    function isWorkspaceScope() {
        return !!(FM && typeof FM.isWorkspaceScope === "function" && FM.isWorkspaceScope());
    }

    function getWorkspaceId() {
        return FM && typeof FM.getWorkspaceId === "function"
            ? String(FM.getWorkspaceId() || "")
            : "";
    }

    function getCurrentRelPathFor(item) {
        if (FM && typeof FM.currentRelPathFor === "function") {
            return String(FM.currentRelPathFor(item) || "");
        }
        return item && item.name ? String(item.name) : "";
    }

    function fmtSize(n) {
        if (FM && typeof FM.fmtSize === "function") return FM.fmtSize(n);
        return `${Number(n || 0)} B`;
    }

    function apiReadCurrentTextUrl(path) {
        if (FM && FM.api && typeof FM.api.readTextUrl === "function") {
            return FM.api.readTextUrl(path || "");
        }

        const qs = new URLSearchParams();
        qs.set("path", path || "");
        return `/api/v4/files/read_text?${qs.toString()}`;
    }

    function apiReadVersionTextUrl(path, versionId) {
        const qs = new URLSearchParams();
        qs.set("path", path || "");
        qs.set("version_id", versionId || "");

        if (isWorkspaceScope()) {
            qs.set("workspace_id", getWorkspaceId());
            return `/api/v4/workspaces/files/versions/read_text?${qs.toString()}`;
        }

        return `/api/v4/files/versions/read_text?${qs.toString()}`;
    }

    function injectCss() {
        if (document.getElementById("pqFileVersionCompareCss")) return;

        const style = document.createElement("style");
        style.id = "pqFileVersionCompareCss";
        style.textContent = `
.pqfvcRoot{
    position:fixed;
    inset:0;
    display:none;
    pointer-events:none;
    z-index:11000;
}
.pqfvcRoot.show{display:block;}
.pqfvcPanel{
    position:absolute;
    left:50%;
    top:72px;
    transform:translateX(-50%);
    width:min(1220px,calc(100vw - 32px));
    height:min(820px,calc(100vh - 96px));
    min-width:min(720px,calc(100vw - 32px));
    min-height:420px;
    max-width:calc(100vw - 24px);
    max-height:calc(100vh - 24px);
    display:flex;
    flex-direction:column;
    overflow:hidden;
    resize:both;
    pointer-events:auto;
    border:1px solid var(--border2,rgba(255,255,255,.18));
    border-radius:0;
    background:var(--fm_surface,var(--panel,#050712));
    color:var(--fg,#eee);
    box-shadow:0 22px 70px rgba(0,0,0,.72);
}
.pqfvcHead{
    cursor:move;
    display:flex;
    align-items:flex-start;
    justify-content:space-between;
    gap:12px;
    padding:13px 15px;
    border-bottom:1px solid var(--border2,rgba(255,255,255,.10));
    background:var(--fm_surface2,var(--panel2,#0b1020));
    user-select:none;
}
html[data-theme="bright"] .pqfvcHead,
html[data-theme="win_classic"] .pqfvcHead{
    background:var(--fm_surface2,var(--panel2,#f4f4f4));
}
.pqfvcTitle{font-weight:950;font-size:15px;color:var(--fg);}
.pqfvcPath{
    margin-top:4px;
    font-size:12px;
    opacity:.78;
    word-break:break-all;
    color:var(--fg);
}
.pqfvcActions{
    display:flex;
    align-items:center;
    gap:8px;
    flex-wrap:wrap;
    cursor:default;
}
.pqfvcSync{
    display:inline-flex;
    align-items:center;
    gap:7px;
    font-size:12px;
    opacity:.9;
    white-space:nowrap;
    color:var(--fg);
}
.pqfvcStatus{
    min-height:36px;
    padding:9px 15px;
    border-bottom:1px solid var(--border2,rgba(255,255,255,.08));
    font-size:13px;
    opacity:.92;
    color:var(--fg);
}
.pqfvcStatus.warn{
    color:rgba(var(--warn-rgb,255,190,0),.98);
    font-weight:800;
}
.pqfvcStatus.err{
    color:rgba(var(--fail-rgb,255,90,90),.98);
    font-weight:850;
}
.pqfvcStatus.ok{
    color:var(--fg);
}
.pqfvcBody{
    flex:1 1 auto;
    min-height:0;
    display:grid;
    grid-template-columns:1fr 1fr;
    gap:0;
}
.pqfvcPane{
    min-width:0;
    min-height:0;
    display:flex;
    flex-direction:column;
}
.pqfvcPane + .pqfvcPane{
    border-left:1px solid var(--border2,rgba(255,255,255,.10));
}
.pqfvcPaneHead{
    padding:10px 12px;
    border-bottom:1px solid var(--border2,rgba(255,255,255,.08));
    background:var(--fm_surface2,var(--panel2,#0b1020));
}
html[data-theme="bright"] .pqfvcPaneHead,
html[data-theme="win_classic"] .pqfvcPaneHead{
    background:var(--fm_surface2,var(--panel2,#f4f4f4));
}
.pqfvcPaneTitle{
    font-weight:900;
    font-size:13px;
    color:var(--fg);
}
.pqfvcPaneMeta{
    margin-top:4px;
    font-size:12px;
    opacity:.72;
    word-break:break-word;
    color:var(--fg);
}
.pqfvcArea{
    flex:1 1 auto;
    min-height:0;
    width:100%;
    overflow:auto;
    background:var(--bg,#050712);
    color:var(--fg,#eee);
    font-family:var(--mono,monospace);
    font-size:13px;
    line-height:1.45;
    tab-size:4;
    white-space:pre;
    user-select:text;
}
html[data-theme="bright"] .pqfvcArea,
html[data-theme="win_classic"] .pqfvcArea{
    background:#ffffff;
}
.pqfvcLine{
    display:grid;
    grid-template-columns:58px minmax(0,1fr);
    min-height:1.45em;
}
.pqfvcLineNo{
    padding:0 10px 0 8px;
    text-align:right;
    opacity:.42;
    border-right:1px solid rgba(var(--fg-rgb,255,255,255),.10);
    user-select:none;
}
.pqfvcLineText{
    padding:0 12px;
    overflow:visible;
}
.pqfvcLine.diff{
    background:rgba(var(--warn-rgb,255,190,0),.24);
}
.pqfvcLine.diff .pqfvcLineNo{
    opacity:.9;
    color:rgba(var(--warn-rgb,255,190,0),1);
    font-weight:900;
}
html[data-theme="bright"] .pqfvcLine.diff,
html[data-theme="win_classic"] .pqfvcLine.diff{
    background:rgba(255,190,0,.28);
}
@media (max-width:760px){
    .pqfvcPanel{
        left:12px !important;
        top:12px !important;
        transform:none !important;
        width:calc(100vw - 24px);
        min-width:0;
        height:calc(100vh - 24px);
    }
    .pqfvcBody{grid-template-columns:1fr;}
    .pqfvcPane + .pqfvcPane{
        border-left:0;
        border-top:1px solid var(--border2,rgba(255,255,255,.10));
    }
}

/* Hard opaque compare window overrides.
   This window floats above File Manager, so theme panel translucency looks bad here. */
.pqfvcPanel{
    background:#02070b !important;
    background-color:#02070b !important;
    border-radius:0 !important;
    opacity:1 !important;
}
.pqfvcHead,
.pqfvcStatus,
.pqfvcPaneHead{
    background:#061119 !important;
    background-color:#061119 !important;
    opacity:1 !important;
}
.pqfvcBody,
.pqfvcPane,
.pqfvcArea{
    background:#02070b !important;
    background-color:#02070b !important;
    opacity:1 !important;
}
.pqfvcLine{
    background:#02070b !important;
}
.pqfvcLine.diff{
    background:#3a3000 !important;
}
html[data-theme="bright"] .pqfvcPanel,
html[data-theme="bright"] .pqfvcBody,
html[data-theme="bright"] .pqfvcPane,
html[data-theme="bright"] .pqfvcArea,
html[data-theme="bright"] .pqfvcLine,
html[data-theme="win_classic"] .pqfvcPanel,
html[data-theme="win_classic"] .pqfvcBody,
html[data-theme="win_classic"] .pqfvcPane,
html[data-theme="win_classic"] .pqfvcArea,
html[data-theme="win_classic"] .pqfvcLine{
    background:#ffffff !important;
    background-color:#ffffff !important;
}
html[data-theme="bright"] .pqfvcHead,
html[data-theme="bright"] .pqfvcStatus,
html[data-theme="bright"] .pqfvcPaneHead,
html[data-theme="win_classic"] .pqfvcHead,
html[data-theme="win_classic"] .pqfvcStatus,
html[data-theme="win_classic"] .pqfvcPaneHead{
    background:#f0f0f0 !important;
    background-color:#f0f0f0 !important;
}
html[data-theme="bright"] .pqfvcLine.diff,
html[data-theme="win_classic"] .pqfvcLine.diff{
    background:#fff1b8 !important;
    background-color:#fff1b8 !important;
}


/* Keep both compare panes aligned even when one side has longer metadata. */
.pqfvcPaneHead{
    height:72px !important;
    min-height:72px !important;
    max-height:72px !important;
    overflow:hidden !important;
}
.pqfvcPaneMeta{
    white-space:nowrap !important;
    overflow:hidden !important;
    text-overflow:ellipsis !important;
    max-width:100% !important;
}
.pqfvcArea{
    border-top:1px solid var(--border2,rgba(255,255,255,.10)) !important;
}

`;
        document.head.appendChild(style);
    }

    function ensureDom() {
        if (rootEl) return;

        injectCss();

        rootEl = document.createElement("div");
        rootEl.className = "pqfvcRoot";
        rootEl.setAttribute("aria-hidden", "true");

        panelEl = document.createElement("div");
        panelEl.className = "pqfvcPanel";
        panelEl.setAttribute("role", "dialog");
        panelEl.setAttribute("aria-modal", "false");

        headEl = document.createElement("div");
        headEl.className = "pqfvcHead";

        const headLeft = document.createElement("div");

        titleEl = document.createElement("div");
        titleEl.className = "pqfvcTitle";
        titleEl.textContent = "Compare file version";

        pathEl = document.createElement("div");
        pathEl.className = "pqfvcPath mono";

        headLeft.appendChild(titleEl);
        headLeft.appendChild(pathEl);

        const actions = document.createElement("div");
        actions.className = "pqfvcActions";

        const syncLabel = document.createElement("label");
        syncLabel.className = "pqfvcSync";

        syncCb = document.createElement("input");
        syncCb.type = "checkbox";
        syncCb.checked = true;
        syncCb.addEventListener("change", () => {
            state.syncScroll = !!syncCb.checked;
        });

        const syncText = document.createElement("span");
        syncText.textContent = "Sync scroll";

        syncLabel.appendChild(syncCb);
        syncLabel.appendChild(syncText);

        const closeBtn = document.createElement("button");
        closeBtn.type = "button";
        closeBtn.className = "btn secondary";
        closeBtn.textContent = "Close";
        closeBtn.addEventListener("click", close);

        actions.appendChild(syncLabel);
        actions.appendChild(closeBtn);

        headEl.appendChild(headLeft);
        headEl.appendChild(actions);

        statusEl = document.createElement("div");
        statusEl.className = "pqfvcStatus";

        const body = document.createElement("div");
        body.className = "pqfvcBody";

        const leftPane = document.createElement("div");
        leftPane.className = "pqfvcPane";

        const leftHead = document.createElement("div");
        leftHead.className = "pqfvcPaneHead";

        const leftTitle = document.createElement("div");
        leftTitle.className = "pqfvcPaneTitle";
        leftTitle.textContent = "Selected version";

        leftMetaEl = document.createElement("div");
        leftMetaEl.className = "pqfvcPaneMeta mono";

        leftHead.appendChild(leftTitle);
        leftHead.appendChild(leftMetaEl);

        leftArea = document.createElement("div");
        leftArea.className = "pqfvcArea";
        leftArea.tabIndex = 0;

        leftPane.appendChild(leftHead);
        leftPane.appendChild(leftArea);

        const rightPane = document.createElement("div");
        rightPane.className = "pqfvcPane";

        const rightHead = document.createElement("div");
        rightHead.className = "pqfvcPaneHead";

        const rightTitle = document.createElement("div");
        rightTitle.className = "pqfvcPaneTitle";
        rightTitle.textContent = "Current file";

        rightMetaEl = document.createElement("div");
        rightMetaEl.className = "pqfvcPaneMeta mono";

        rightHead.appendChild(rightTitle);
        rightHead.appendChild(rightMetaEl);

        rightArea = document.createElement("div");
        rightArea.className = "pqfvcArea";
        rightArea.tabIndex = 0;

        rightPane.appendChild(rightHead);
        rightPane.appendChild(rightArea);

        body.appendChild(leftPane);
        body.appendChild(rightPane);

        panelEl.appendChild(headEl);
        panelEl.appendChild(statusEl);
        panelEl.appendChild(body);

        rootEl.appendChild(panelEl);
        document.body.appendChild(rootEl);

        document.addEventListener("keydown", (e) => {
            if (!rootEl.classList.contains("show")) return;
            if (e.key === "Escape") {
                e.preventDefault();
                close();
            }
        });

        leftArea.addEventListener("scroll", () => syncScroll(leftArea, rightArea));
        rightArea.addEventListener("scroll", () => syncScroll(rightArea, leftArea));

        headEl.addEventListener("pointerdown", beginDrag);
        document.addEventListener("pointermove", moveDrag);
        document.addEventListener("pointerup", endDrag);
        document.addEventListener("pointercancel", endDrag);
        window.addEventListener("resize", clampPanelIntoViewport);
    }

    function beginDrag(e) {
        if (!panelEl) return;
        if (e.target && e.target.closest && e.target.closest("button,input,label")) return;

        const rect = panelEl.getBoundingClientRect();

        drag.active = true;
        drag.moved = false;
        drag.startX = e.clientX;
        drag.startY = e.clientY;
        drag.left = rect.left;
        drag.top = rect.top;

        panelEl.style.transform = "none";
        panelEl.style.left = `${rect.left}px`;
        panelEl.style.top = `${rect.top}px`;

        e.preventDefault();
    }

    function moveDrag(e) {
        if (!drag.active || !panelEl) return;

        const dx = e.clientX - drag.startX;
        const dy = e.clientY - drag.startY;

        if (Math.abs(dx) > 2 || Math.abs(dy) > 2) drag.moved = true;

        const rect = panelEl.getBoundingClientRect();
        const pad = 8;
        const maxLeft = Math.max(pad, window.innerWidth - rect.width - pad);
        const maxTop = Math.max(pad, window.innerHeight - rect.height - pad);

        const left = Math.max(pad, Math.min(maxLeft, drag.left + dx));
        const top = Math.max(pad, Math.min(maxTop, drag.top + dy));

        panelEl.style.left = `${left}px`;
        panelEl.style.top = `${top}px`;
    }

    function endDrag() {
        drag.active = false;
    }

    function clampPanelIntoViewport() {
        if (!panelEl || !rootEl || !rootEl.classList.contains("show")) return;

        const rect = panelEl.getBoundingClientRect();
        const pad = 8;

        let left = rect.left;
        let top = rect.top;

        const maxLeft = Math.max(pad, window.innerWidth - rect.width - pad);
        const maxTop = Math.max(pad, window.innerHeight - rect.height - pad);

        left = Math.max(pad, Math.min(maxLeft, left));
        top = Math.max(pad, Math.min(maxTop, top));

        panelEl.style.transform = "none";
        panelEl.style.left = `${left}px`;
        panelEl.style.top = `${top}px`;
    }

    function syncScroll(src, dst) {
        if (!state.syncScroll || scrolling || !src || !dst) return;

        scrolling = true;

        const srcMax = Math.max(1, src.scrollHeight - src.clientHeight);
        const dstMax = Math.max(0, dst.scrollHeight - dst.clientHeight);
        dst.scrollTop = (src.scrollTop / srcMax) * dstMax;

        window.requestAnimationFrame(() => {
            scrolling = false;
        });
    }

    function setStatus(text, kind = "") {
        if (!statusEl) return;
        statusEl.className = `pqfvcStatus${kind ? " " + kind : ""}`;
        statusEl.textContent = text || "";
    }

    function show() {
        ensureDom();

        if (!rootEl.classList.contains("show")) {
            panelEl.style.transform = "translateX(-50%)";
            panelEl.style.left = "50%";
            panelEl.style.top = "72px";
        }

        rootEl.classList.add("show");
        rootEl.setAttribute("aria-hidden", "false");
        setTimeout(clampPanelIntoViewport, 0);
    }

    function close() {
        if (!rootEl) return;
        rootEl.classList.remove("show");
        rootEl.setAttribute("aria-hidden", "true");
        if (leftArea) leftArea.replaceChildren();
        if (rightArea) rightArea.replaceChildren();
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

    function splitLinesPreserveLast(text) {
        return String(text || "").split("\n");
    }

    function changedLineSet(a, b) {
        const aa = splitLinesPreserveLast(a);
        const bb = splitLinesPreserveLast(b);
        const n = Math.max(aa.length, bb.length);
        const changed = new Set();

        for (let i = 0; i < n; i++) {
            if ((aa[i] || "") !== (bb[i] || "")) changed.add(i);
        }

        return changed;
    }

    function renderTextPane(container, text, changed) {
        container.replaceChildren();

        const lines = splitLinesPreserveLast(text);
        const frag = document.createDocumentFragment();

        for (let i = 0; i < lines.length; i++) {
            const row = document.createElement("div");
            row.className = "pqfvcLine" + (changed && changed.has(i) ? " diff" : "");

            const no = document.createElement("div");
            no.className = "pqfvcLineNo";
            no.textContent = String(i + 1);

            const code = document.createElement("div");
            code.className = "pqfvcLineText";
            code.textContent = lines[i] || " ";

            row.appendChild(no);
            row.appendChild(code);
            frag.appendChild(row);
        }

        container.appendChild(frag);
    }

    async function openCompare(item, version) {
        if (!item || item.type !== "file" || !version || !version.version_id) return;

        ensureDom();

        state.item = item;
        state.version = version;
        state.relPath = getCurrentRelPathFor(item);
        state.loading = true;

        titleEl.textContent = "Compare file version";
        pathEl.textContent = "/" + state.relPath;
        leftMetaEl.textContent = "Loading selected version…";
        rightMetaEl.textContent = "Loading current file…";
        leftArea.replaceChildren();
        rightArea.replaceChildren();

        show();
        setStatus("Loading texts…", "warn");

        try {
            const [oldJ, curJ] = await Promise.all([
                fetchJson(apiReadVersionTextUrl(state.relPath, version.version_id)),
                fetchJson(apiReadCurrentTextUrl(state.relPath))
            ]);

            const oldText = String(oldJ.text || "");
            const curText = String(curJ.text || "");

            const changed = changedLineSet(oldText, curText);

            renderTextPane(leftArea, oldText, changed);
            renderTextPane(rightArea, curText, changed);

            leftArea.scrollTop = 0;
            rightArea.scrollTop = 0;

            leftMetaEl.textContent =
                `${oldJ.created_at || version.created_at || ""} • ${fmtSize(oldJ.bytes || version.bytes || 0)} • ${oldJ.sha256 || oldJ.sha256_hex || version.sha256_hex || ""}`;

            rightMetaEl.textContent =
                `${fmtSize(new Blob([curText]).size)} • ${curJ.sha256 || ""}`;

            setStatus(
                changed.size
                    ? `Loaded. Highlighted changed line positions: ${changed.size}`
                    : "Loaded. No line-position differences found.",
                "ok"
            );
        } catch (e) {
            setStatus(String(e && e.message ? e.message : e), "err");
        } finally {
            state.loading = false;
        }
    }

    FM.fileVersionCompare = {
        canCompare(item) {
            if (!item || item.type !== "file") return false;
            const rel = getCurrentRelPathFor(item);
            return isTextName(rel || item.name || "");
        },
        open: openCompare,
        close
    };
})();
