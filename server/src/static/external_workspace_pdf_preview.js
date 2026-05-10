(() => {
    "use strict";

    if (window.__pqnasExternalPdfPreviewDetachedV1) return;
    window.__pqnasExternalPdfPreviewDetachedV1 = true;

    const params = new URLSearchParams(location.search);
    const workspaceId = String(params.get("workspace_id") || "").trim();

    const state = {
        relPath: "",
        root: null,
        card: null,
        head: null,
        title: null,
        path: null,
        info: null,
        frame: null,
        objectUrl: "",
        abort: null,
        prevBtn: null,
        nextBtn: null,
        openBtn: null,
        drag: null
    };

    function normalizeRelPath(p) {
        let v = String(p || "").trim().replaceAll("\\", "/");
        while (v.startsWith("/")) v = v.slice(1);
        while (v.endsWith("/") && v.length > 1) v = v.slice(0, -1);
        if (v === "." || v === "/") return "";
        return v;
    }

    function basenameFromPath(p) {
        const v = normalizeRelPath(p);
        if (!v) return "";
        const i = v.lastIndexOf("/");
        return i >= 0 ? v.slice(i + 1) : v;
    }

    function isPdfName(name) {
        return /\.pdf$/i.test(String(name || "").split("?")[0].split("#")[0]);
    }

    function pdfUrl(relPath) {
        const qs = new URLSearchParams();
        qs.set("workspace_id", workspaceId);
        qs.set("path", normalizeRelPath(relPath));
        return `/api/v4/workspaces/files/get?${qs.toString()}`;
    }

    function rowsInView() {
        return Array.from(document.querySelectorAll("#files .fileRow[data-file]"));
    }

    function rowToItem(row) {
        if (!row) return null;
        const rel = normalizeRelPath(row.dataset.file || "");
        const name = row.dataset.name || basenameFromPath(rel);
        if (!rel || !isPdfName(name || rel)) return null;
        return { rel, name };
    }

    function pdfItemsInView() {
        return rowsInView().map(rowToItem).filter(Boolean);
    }

    function currentIndex() {
        const items = pdfItemsInView();
        const idx = items.findIndex((it) => it.rel === state.relPath);
        return { items, idx };
    }

    function injectStyles() {
        if (document.getElementById("externalPdfPreviewStyles")) return;

        const style = document.createElement("style");
        style.id = "externalPdfPreviewStyles";
        style.textContent = `
.externalPdfPreviewOverlay{
    position:fixed;
    inset:0;
    z-index:9060;
    display:none;
    pointer-events:none;
    background:transparent;
}

.externalPdfPreviewOverlay.show{
    display:block;
}

.externalPdfPreviewCard{
    position:fixed;
    left:50%;
    top:34px;
    width:min(1180px, calc(100vw - 42px));
    height:min(88vh, 920px);
    transform:translateX(-50%);
    display:flex;
    flex-direction:column;
    overflow:hidden;
    pointer-events:auto;
    border:1px solid rgba(255,255,255,.16);
    border-radius:18px;
    background:linear-gradient(180deg, rgba(32,32,32,.98), rgba(18,18,18,.98));
    box-shadow:0 28px 110px rgba(0,0,0,.52);
    color:var(--fg);
}

.externalPdfPreviewCard.dragging{
    user-select:none;
}

.externalPdfPreviewHead{
    flex:0 0 auto;
    display:flex;
    align-items:flex-start;
    justify-content:space-between;
    gap:12px;
    padding:12px 14px;
    border-bottom:1px solid rgba(255,255,255,.14);
    background:rgba(0,0,0,.18);
    cursor:grab;
    user-select:none;
    touch-action:none;
}

.externalPdfPreviewCard.dragging .externalPdfPreviewHead{
    cursor:grabbing;
}

.externalPdfPreviewTitle{
    font-weight:950;
    letter-spacing:.2px;
    font-size:16px;
}

.externalPdfPreviewPath{
    margin-top:2px;
    font-size:12px;
    color:var(--muted);
    white-space:nowrap;
    overflow:hidden;
    text-overflow:ellipsis;
    max-width:78ch;
}

.externalPdfPreviewActions{
    display:flex;
    align-items:center;
    gap:8px;
    flex-wrap:wrap;
    justify-content:flex-end;
}

.externalPdfPreviewInfo{
    flex:0 0 auto;
    padding:9px 14px;
    border-bottom:1px solid rgba(255,255,255,.10);
    color:var(--muted);
    font-size:12px;
    line-height:1.35;
}

.externalPdfPreviewBody{
    flex:1 1 auto;
    min-height:0;
    background:rgba(0,0,0,.26);
}

.externalPdfPreviewFrame{
    display:block;
    width:100%;
    height:100%;
    border:0;
    background:#fff;
}

html[data-theme="win_classic"] .externalPdfPreviewCard{
    background:rgb(245,245,245);
    color:#050505;
    border:2px solid rgba(0,0,0,.55);
    border-radius:2px;
    box-shadow:6px 6px 0 rgba(0,0,0,.22);
}

html[data-theme="win_classic"] .externalPdfPreviewHead{
    background:rgba(0,0,0,.055);
    border-bottom:1px solid rgba(0,0,0,.18);
}

html[data-theme="win_classic"] .externalPdfPreviewPath,
html[data-theme="win_classic"] .externalPdfPreviewInfo{
    color:#4d5662;
}

html[data-theme="win_classic"] .externalPdfPreviewInfo{
    background:#e9edf2;
    border-bottom-color:rgba(0,0,0,.14);
}

html[data-theme="win_classic"] .externalPdfPreviewBody{
    background:#d8d8d8;
}

@media (max-width:720px){
    .externalPdfPreviewCard{
        width:calc(100vw - 20px);
        height:calc(100vh - 20px);
        top:10px;
    }
}
        `;
        document.head.appendChild(style);
    }

    function makeButton(text, cls = "btn secondary") {
        const b = document.createElement("button");
        b.type = "button";
        b.className = cls;
        b.textContent = text;
        return b;
    }

    function ensureDom() {
        if (state.root) return;

        injectStyles();

        const root = document.createElement("div");
        root.className = "externalPdfPreviewOverlay";
        root.setAttribute("aria-hidden", "true");

        root.innerHTML = `
            <div class="externalPdfPreviewCard" role="dialog" aria-modal="true" aria-label="PDF preview">
                <div class="externalPdfPreviewHead">
                    <div>
                        <div class="externalPdfPreviewTitle">PDF preview</div>
                        <div class="externalPdfPreviewPath mono">/</div>
                    </div>
                    <div class="externalPdfPreviewActions"></div>
                </div>
                <div class="externalPdfPreviewInfo">Loading…</div>
                <div class="externalPdfPreviewBody">
                    <iframe class="externalPdfPreviewFrame" title="PDF preview"></iframe>
                </div>
            </div>
        `;

        document.body.appendChild(root);

        state.root = root;
        state.card = root.querySelector(".externalPdfPreviewCard");
        state.head = root.querySelector(".externalPdfPreviewHead");
        state.title = root.querySelector(".externalPdfPreviewTitle");
        state.path = root.querySelector(".externalPdfPreviewPath");
        state.info = root.querySelector(".externalPdfPreviewInfo");
        state.frame = root.querySelector(".externalPdfPreviewFrame");

        const actions = root.querySelector(".externalPdfPreviewActions");
        state.prevBtn = makeButton("‹");
        state.nextBtn = makeButton("›");
        state.openBtn = makeButton("Open original");
        const closeBtn = makeButton("Close");

        state.prevBtn.title = "Previous PDF";
        state.nextBtn.title = "Next PDF";
        state.openBtn.title = "Open original PDF in new tab";

        actions.appendChild(state.prevBtn);
        actions.appendChild(state.nextBtn);
        actions.appendChild(state.openBtn);
        actions.appendChild(closeBtn);

        closeBtn.addEventListener("click", closePreview);
        state.prevBtn.addEventListener("click", openPrev);
        state.nextBtn.addEventListener("click", openNext);
        state.openBtn.addEventListener("click", () => {
            if (!state.relPath) return;
            window.open(pdfUrl(state.relPath), "_blank", "noopener");
        });

        state.head.addEventListener("pointerdown", beginDrag);
        state.head.addEventListener("pointermove", moveDrag);
        state.head.addEventListener("pointerup", endDrag);
        state.head.addEventListener("pointercancel", endDrag);

        document.addEventListener("keydown", (ev) => {
            if (!previewOpen()) return;

            if (ev.key === "Escape") {
                ev.preventDefault();
                closePreview();
                return;
            }

            if (ev.key === "ArrowLeft") {
                ev.preventDefault();
                openPrev();
                return;
            }

            if (ev.key === "ArrowRight") {
                ev.preventDefault();
                openNext();
            }
        });

        window.addEventListener("resize", () => {
            if (previewOpen()) clampIntoViewport();
        });
    }

    function updateNavButtons() {
        const { items, idx } = currentIndex();
        const many = items.length > 1 && idx >= 0;
        if (state.prevBtn) state.prevBtn.disabled = !many;
        if (state.nextBtn) state.nextBtn.disabled = !many;
    }

    function openByIndex(nextIdx) {
        const { items } = currentIndex();
        if (!items.length) return;
        const idx = ((nextIdx % items.length) + items.length) % items.length;
        openPreview(items[idx]);
    }

    function openPrev() {
        const { idx } = currentIndex();
        if (idx < 0) return;
        openByIndex(idx - 1);
    }

    function openNext() {
        const { idx } = currentIndex();
        if (idx < 0) return;
        openByIndex(idx + 1);
    }

    function placeCentered() {
        if (!state.card) return;
        state.card.style.left = "50%";
        state.card.style.top = "34px";
        state.card.style.transform = "translateX(-50%)";
    }

    function clamp(n, lo, hi) {
        return Math.max(lo, Math.min(hi, n));
    }

    function clampIntoViewport() {
        if (!state.card) return;

        const rect = state.card.getBoundingClientRect();
        const pad = 8;

        const left = clamp(rect.left, pad, Math.max(pad, window.innerWidth - rect.width - pad));
        const top = clamp(rect.top, pad, Math.max(pad, window.innerHeight - rect.height - pad));

        state.card.style.transform = "none";
        state.card.style.left = `${left}px`;
        state.card.style.top = `${top}px`;
    }

    function clearPdfObjectUrl() {
        try {
            if (state.abort) state.abort.abort();
        } catch (_) {}
        state.abort = null;

        if (state.frame) state.frame.removeAttribute("src");

        if (state.objectUrl) {
            try { URL.revokeObjectURL(state.objectUrl); } catch (_) {}
            state.objectUrl = "";
        }
    }

    async function loadPdfBlobIntoFrame(relPath) {
        clearPdfObjectUrl();

        const controller = new AbortController();
        state.abort = controller;

        const r = await fetch(pdfUrl(relPath), {
            method: "GET",
            credentials: "include",
            cache: "no-store",
            headers: { "Accept": "application/pdf,*/*" },
            signal: controller.signal
        });

        if (!r.ok) {
            throw new Error("HTTP " + r.status);
        }

        const blob = await r.blob();

        if (controller.signal.aborted) return;

        const pdfBlob = blob.type === "application/pdf"
            ? blob
            : new Blob([blob], { type: "application/pdf" });

        state.objectUrl = URL.createObjectURL(pdfBlob);

        if (state.frame) {
            state.frame.src = state.objectUrl + "#toolbar=1&navpanes=0";
        }
    }

    function openPreview(item) {
        if (!item || !item.rel) return;

        ensureDom();

        state.relPath = normalizeRelPath(item.rel);

        if (state.title) state.title.textContent = "PDF preview";
        if (state.path) state.path.textContent = "/" + state.relPath;
        if (state.info) state.info.textContent = basenameFromPath(state.relPath) || "PDF document";

        if (state.frame) {
            state.frame.removeAttribute("src");
        }

        loadPdfBlobIntoFrame(state.relPath)
            .then(() => {
                const { items, idx } = currentIndex();
                const pos = idx >= 0 && items.length > 1 ? ` • ${idx + 1} / ${items.length}` : "";
                if (state.info) state.info.textContent = `${basenameFromPath(state.relPath) || "PDF document"}${pos}`;
                updateNavButtons();
            })
            .catch((e) => {
                if (e && e.name === "AbortError") return;
                if (state.info) state.info.textContent = `PDF preview failed: ${e && e.message ? e.message : e}`;
            });

        document.body.classList.add("externalPdfPreviewOpen");

        placeCentered();
        state.root.classList.add("show");
        state.root.setAttribute("aria-hidden", "false");
        updateNavButtons();
    }

    function closePreview() {
        if (!state.root) return;

        state.root.classList.remove("show");
        state.root.setAttribute("aria-hidden", "true");
        document.body.classList.remove("externalPdfPreviewOpen");

        clearPdfObjectUrl();
        state.relPath = "";
    }

    function beginDrag(ev) {
        if (!state.card || !state.head) return;
        if (ev.button !== 0) return;
        if (ev.target.closest("button, input, textarea, select, a")) return;

        const rect = state.card.getBoundingClientRect();
        state.drag = {
            pointerId: ev.pointerId,
            startX: ev.clientX,
            startY: ev.clientY,
            left: rect.left,
            top: rect.top
        };

        state.card.classList.add("dragging");
        state.card.style.position = "fixed";
        state.card.style.transform = "none";
        state.card.style.left = `${rect.left}px`;
        state.card.style.top = `${rect.top}px`;

        try { state.head.setPointerCapture(ev.pointerId); } catch (_) {}

        ev.preventDefault();
        ev.stopPropagation();
        if (typeof ev.stopImmediatePropagation === "function") ev.stopImmediatePropagation();
    }

    function moveDrag(ev) {
        if (!state.drag || !state.card || ev.pointerId !== state.drag.pointerId) return;

        const dx = ev.clientX - state.drag.startX;
        const dy = ev.clientY - state.drag.startY;
        const rect = state.card.getBoundingClientRect();
        const pad = 8;

        const left = clamp(
            state.drag.left + dx,
            pad,
            Math.max(pad, window.innerWidth - rect.width - pad)
        );

        const top = clamp(
            state.drag.top + dy,
            pad,
            Math.max(pad, window.innerHeight - rect.height - pad)
        );

        state.card.style.left = `${left}px`;
        state.card.style.top = `${top}px`;

        ev.preventDefault();
        ev.stopPropagation();
        if (typeof ev.stopImmediatePropagation === "function") ev.stopImmediatePropagation();
    }

    function endDrag(ev) {
        if (!state.drag || ev.pointerId !== state.drag.pointerId) return;

        if (state.card) state.card.classList.remove("dragging");
        try { state.head && state.head.releasePointerCapture(ev.pointerId); } catch (_) {}

        state.drag = null;

        ev.preventDefault();
        ev.stopPropagation();
        if (typeof ev.stopImmediatePropagation === "function") ev.stopImmediatePropagation();
    }

    function previewOpen() {
        return !!(state.root && state.root.classList.contains("show"));
    }

    // Block workspace marquee while PDF preview is open.
    window.addEventListener("pointerdown", (ev) => {
        if (!previewOpen()) return;

        const insideCard = state.card && state.card.contains(ev.target);
        if (!insideCard) {
            ev.preventDefault();
        }

        ev.stopPropagation();
        if (typeof ev.stopImmediatePropagation === "function") ev.stopImmediatePropagation();
    }, true);

    document.addEventListener("dblclick", (ev) => {
        const row = ev.target && ev.target.closest ? ev.target.closest("#files .fileRow[data-file]") : null;
        if (!row) return;

        const item = rowToItem(row);
        if (!item) return;

        ev.preventDefault();
        ev.stopPropagation();
        if (typeof ev.stopImmediatePropagation === "function") ev.stopImmediatePropagation();

        openPreview(item);
    }, true);

    window.PQNAS_EXTERNAL_PDF_PREVIEW = {
        open: openPreview,
        isPdfName
    };
})();
