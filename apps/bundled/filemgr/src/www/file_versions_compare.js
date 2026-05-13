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
        hideUnchanged: false,
        loading: false,
        lastDiff: null
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
    let hideCb = null;
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


/* Git-style +/- line diff rendering. */
.pqfvcLine{
    grid-template-columns:58px 24px minmax(0,1fr) !important;
}
.pqfvcMark{
    padding:0 6px;
    text-align:center;
    font-weight:950;
    user-select:none;
    opacity:.95;
}
.pqfvcLine.del{
    background:rgba(180,40,40,.24) !important;
}
.pqfvcLine.ins{
    background:rgba(40,150,80,.24) !important;
}
.pqfvcLine.spacer{
    opacity:.42;
}
.pqfvcLine.del .pqfvcMark{
    color:#ff7070;
}
.pqfvcLine.ins .pqfvcMark{
    color:#5ee27a;
}
html[data-theme="bright"] .pqfvcLine.del,
html[data-theme="win_classic"] .pqfvcLine.del{
    background:#ffe0e0 !important;
}
html[data-theme="bright"] .pqfvcLine.ins,
html[data-theme="win_classic"] .pqfvcLine.ins{
    background:#ddf7e5 !important;
}
html[data-theme="bright"] .pqfvcLine.del .pqfvcMark,
html[data-theme="win_classic"] .pqfvcLine.del .pqfvcMark{
    color:#b00020;
}
html[data-theme="bright"] .pqfvcLine.ins .pqfvcMark,
html[data-theme="win_classic"] .pqfvcLine.ins .pqfvcMark{
    color:#107c41;
}


/* Collapsed unchanged sections. */
.pqfvcLine.skip{
    background:#07151f !important;
    opacity:.86;
}
.pqfvcLine.skip .pqfvcMark{
    color:var(--fg);
    opacity:.7;
}
.pqfvcLine.skip .pqfvcLineText{
    font-style:italic;
    opacity:.72;
}
html[data-theme="bright"] .pqfvcLine.skip,
html[data-theme="win_classic"] .pqfvcLine.skip{
    background:#eeeeee !important;
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

        const hideLabel = document.createElement("label");
        hideLabel.className = "pqfvcSync";

        hideCb = document.createElement("input");
        hideCb.type = "checkbox";
        hideCb.checked = !!state.hideUnchanged;
        hideCb.addEventListener("change", () => {
            state.hideUnchanged = !!hideCb.checked;
            rerenderCurrentDiff();
        });

        const hideText = document.createElement("span");
        hideText.textContent = "Hide unchanged";

        hideLabel.appendChild(hideCb);
        hideLabel.appendChild(hideText);

        const closeBtn = document.createElement("button");
        closeBtn.type = "button";
        closeBtn.className = "btn secondary";
        closeBtn.textContent = "Close";
        closeBtn.addEventListener("click", close);

        actions.appendChild(syncLabel);
        actions.appendChild(hideLabel);
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
        state.lastDiff = null;
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

    function buildAlignedDiffRows(oldText, curText) {
        const oldLines = splitLinesPreserveLast(oldText);
        const curLines = splitLinesPreserveLast(curText);

        const m = oldLines.length;
        const n = curLines.length;
        const product = m * n;

        if (product > 2000000) {
            return buildLinePositionFallback(oldLines, curLines);
        }

        const dp = new Array(m + 1);
        for (let i = 0; i <= m; i++) {
            dp[i] = new Uint32Array(n + 1);
        }

        for (let i = m - 1; i >= 0; i--) {
            const row = dp[i];
            const next = dp[i + 1];

            for (let j = n - 1; j >= 0; j--) {
                if (oldLines[i] === curLines[j]) {
                    row[j] = next[j + 1] + 1;
                } else {
                    row[j] = Math.max(next[j], row[j + 1]);
                }
            }
        }

        const ops = [];
        let i = 0;
        let j = 0;

        while (i < m && j < n) {
            if (oldLines[i] === curLines[j]) {
                ops.push({
                    kind: "equal",
                    leftNo: i + 1,
                    rightNo: j + 1,
                    leftText: oldLines[i],
                    rightText: curLines[j]
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
                    rightText: curLines[j]
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
                rightText: curLines[j]
            });
            j++;
        }

        return coalesceDiffOps(ops, false);
    }

    function buildLinePositionFallback(oldLines, curLines) {
        const rows = [];
        const stats = { inserted: 0, deleted: 0, changed: 0 };
        const n = Math.max(oldLines.length, curLines.length);

        for (let i = 0; i < n; i++) {
            const hasLeft = i < oldLines.length;
            const hasRight = i < curLines.length;
            const leftText = hasLeft ? oldLines[i] : "";
            const rightText = hasRight ? curLines[i] : "";

            if (hasLeft && hasRight && leftText === rightText) {
                rows.push({
                    kind: "equal",
                    leftNo: i + 1,
                    rightNo: i + 1,
                    leftText,
                    rightText
                });
            } else if (hasLeft && hasRight) {
                stats.changed++;
                rows.push({
                    kind: "replace",
                    leftNo: i + 1,
                    rightNo: i + 1,
                    leftText,
                    rightText
                });
            } else if (hasLeft) {
                stats.deleted++;
                rows.push({
                    kind: "delete",
                    leftNo: i + 1,
                    rightNo: "",
                    leftText,
                    rightText: ""
                });
            } else {
                stats.inserted++;
                rows.push({
                    kind: "insert",
                    leftNo: "",
                    rightNo: i + 1,
                    leftText: "",
                    rightText
                });
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

        const changed = new Set();

        for (let i = 0; i < rows.length; i++) {
            const k = rows[i] && rows[i].kind;
            if (k && k !== "equal" && k !== "skip") {
                for (let j = Math.max(0, i - context); j <= Math.min(rows.length - 1, i + context); j++) {
                    changed.add(j);
                }
            }
        }

        if (!changed.size) return rows;

        const out = [];
        let i = 0;

        while (i < rows.length) {
            if (changed.has(i)) {
                out.push(rows[i]);
                i++;
                continue;
            }

            let j = i;
            while (j < rows.length && !changed.has(j)) j++;

            const hiddenCount = j - i;
            if (hiddenCount > 0) {
                out.push({
                    kind: "skip",
                    count: hiddenCount,
                    leftNo: "",
                    rightNo: "",
                    leftText: "",
                    rightText: ""
                });
            }

            i = j;
        }

        return out;
    }

    function rowsForCurrentMode() {
        if (!state.lastDiff || !Array.isArray(state.lastDiff.rows)) return [];
        return state.hideUnchanged
            ? compactUnchangedRows(state.lastDiff.rows, 3)
            : state.lastDiff.rows;
    }

    function rerenderCurrentDiff() {
        if (!state.lastDiff || !leftArea || !rightArea) return;

        const leftTop = leftArea.scrollTop || 0;
        const rightTop = rightArea.scrollTop || 0;

        const rows = rowsForCurrentMode();
        renderDiffPane(leftArea, rows, "left");
        renderDiffPane(rightArea, rows, "right");

        leftArea.scrollTop = Math.min(leftTop, Math.max(0, leftArea.scrollHeight - leftArea.clientHeight));
        rightArea.scrollTop = Math.min(rightTop, Math.max(0, rightArea.scrollHeight - rightArea.clientHeight));
    }

    function renderDiffPane(container, rows, side) {
        container.replaceChildren();

        const isLeft = side === "left";
        const frag = document.createDocumentFragment();

        for (const r of rows) {
            if (r && r.kind === "skip") {
                const row = document.createElement("div");
                row.className = "pqfvcLine skip";

                const no = document.createElement("div");
                no.className = "pqfvcLineNo";
                no.textContent = "";

                const markEl = document.createElement("div");
                markEl.className = "pqfvcMark";
                markEl.textContent = "⋯";

                const code = document.createElement("div");
                code.className = "pqfvcLineText";
                code.textContent = `${Number(r.count || 0)} unchanged line(s) hidden`;

                row.appendChild(no);
                row.appendChild(markEl);
                row.appendChild(code);
                frag.appendChild(row);
                continue;
            }

            const hasText = isLeft
                ? (r.leftNo !== "" && r.leftNo != null)
                : (r.rightNo !== "" && r.rightNo != null);

            let cls = "pqfvcLine";
            let mark = "";
            let lineNo = "";
            let text = "";

            if (isLeft) {
                lineNo = r.leftNo || "";
                text = hasText ? String(r.leftText ?? "") : "";

                if (r.kind === "delete" || r.kind === "replace") {
                    cls += " del";
                    mark = "-";
                } else if (r.kind === "insert") {
                    cls += " spacer";
                }
            } else {
                lineNo = r.rightNo || "";
                text = hasText ? String(r.rightText ?? "") : "";

                if (r.kind === "insert" || r.kind === "replace") {
                    cls += " ins";
                    mark = "+";
                } else if (r.kind === "delete") {
                    cls += " spacer";
                }
            }

            const row = document.createElement("div");
            row.className = cls;

            const no = document.createElement("div");
            no.className = "pqfvcLineNo";
            no.textContent = lineNo ? String(lineNo) : "";

            const markEl = document.createElement("div");
            markEl.className = "pqfvcMark";
            markEl.textContent = mark;

            const code = document.createElement("div");
            code.className = "pqfvcLineText";
            code.textContent = hasText ? (text || " ") : " ";

            row.appendChild(no);
            row.appendChild(markEl);
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

            const diff = buildAlignedDiffRows(oldText, curText);
            state.lastDiff = diff;

            const rows = rowsForCurrentMode();
            renderDiffPane(leftArea, rows, "left");
            renderDiffPane(rightArea, rows, "right");

            leftArea.scrollTop = 0;
            rightArea.scrollTop = 0;

            leftMetaEl.textContent =
                `${oldJ.created_at || version.created_at || ""} • ${fmtSize(oldJ.bytes || version.bytes || 0)} • ${oldJ.sha256 || oldJ.sha256_hex || version.sha256_hex || ""}`;

            rightMetaEl.textContent =
                `${fmtSize(new Blob([curText]).size)} • ${curJ.sha256 || ""}`;

            const total = diff.stats.inserted + diff.stats.deleted + diff.stats.changed;
            const parts = [];
            if (diff.stats.inserted) parts.push(`+${diff.stats.inserted} added`);
            if (diff.stats.deleted) parts.push(`-${diff.stats.deleted} removed`);
            if (diff.stats.changed) parts.push(`~${diff.stats.changed} changed`);

            setStatus(
                total
                    ? `Loaded. ${parts.join(" • ")}${diff.fallback ? " • large-file fallback" : ""}`
                    : "Loaded. No line differences found.",
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
