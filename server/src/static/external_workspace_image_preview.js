(() => {
    "use strict";

    const params = new URLSearchParams(location.search);
    const workspaceId = String(params.get("workspace_id") || "").trim();

    const IMAGE_EXTS = new Set([
        "jpg", "jpeg", "png", "gif", "webp", "bmp", "svg", "avif"
    ]);

    const state = {
        relPath: "",
        mode: "fit",
        root: null,
        card: null,
        head: null,
        title: null,
        path: null,
        info: null,
        img: null,
        prevBtn: null,
        nextBtn: null,
        fitBtn: null,
        actualBtn: null,
        openBtn: null,
        drag: null,
        moved: false
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

    function fileExt(name) {
        const n = String(name || "").split("?")[0].split("#")[0].toLowerCase();
        const i = n.lastIndexOf(".");
        return i >= 0 ? n.slice(i + 1) : "";
    }

    function isImageName(name) {
        return IMAGE_EXTS.has(fileExt(name));
    }

    function imageUrl(relPath) {
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
        if (!rel || !isImageName(name || rel)) return null;
        return { rel, name };
    }

    function imageItemsInView() {
        return rowsInView().map(rowToItem).filter(Boolean);
    }

    function currentIndex() {
        const items = imageItemsInView();
        const idx = items.findIndex((it) => it.rel === state.relPath);
        return { items, idx };
    }

    function escapeHtml(s) {
        return String(s == null ? "" : s)
            .replaceAll("&", "&amp;")
            .replaceAll("<", "&lt;")
            .replaceAll(">", "&gt;")
            .replaceAll('"', "&quot;")
            .replaceAll("'", "&#39;");
    }

    function injectStyles() {
        if (document.getElementById("externalImagePreviewStyles")) return;

        const style = document.createElement("style");
        style.id = "externalImagePreviewStyles";
        style.textContent = `
.externalImagePreviewOverlay{
    position:fixed;
    inset:0;
    z-index:9050;
    display:none;
    pointer-events:auto;
    background:transparent;
}

.externalImagePreviewOverlay.show{
    display:block;
}

.externalImagePreviewCard{
    position:fixed;
    left:50%;
    top:42px;
    width:min(1120px, calc(100vw - 42px));
    height:min(82vh, 860px);
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

.externalImagePreviewCard.dragging{
    user-select:none;
}

.externalImagePreviewHead{
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

.externalImagePreviewCard.dragging .externalImagePreviewHead{
    cursor:grabbing;
}

.externalImagePreviewTitle{
    font-weight:950;
    letter-spacing:.2px;
    font-size:16px;
}

.externalImagePreviewPath{
    margin-top:2px;
    font-size:12px;
    color:var(--muted);
    white-space:nowrap;
    overflow:hidden;
    text-overflow:ellipsis;
    max-width:76ch;
}

.externalImagePreviewActions{
    display:flex;
    align-items:center;
    gap:8px;
    flex-wrap:wrap;
    justify-content:flex-end;
}

.externalImagePreviewInfo{
    flex:0 0 auto;
    padding:9px 14px;
    border-bottom:1px solid rgba(255,255,255,.10);
    color:var(--muted);
    font-size:12px;
    line-height:1.35;
}

.externalImagePreviewBody{
    flex:1 1 auto;
    min-height:0;
    overflow:auto;
    display:flex;
    align-items:center;
    justify-content:center;
    background:rgba(0,0,0,.26);
    padding:12px;
}

.externalImagePreviewImg{
    display:block;
    max-width:100%;
    max-height:100%;
    width:auto;
    height:auto;
    object-fit:contain;
}

.externalImagePreviewImg.actual{
    max-width:none;
    max-height:none;
}

html[data-theme="win_classic"] .externalImagePreviewCard{
    background:rgb(245,245,245);
    color:#050505;
    border:2px solid rgba(0,0,0,.55);
    border-radius:2px;
    box-shadow:6px 6px 0 rgba(0,0,0,.22);
}

html[data-theme="win_classic"] .externalImagePreviewHead{
    background:rgba(0,0,0,.055);
    border-bottom:1px solid rgba(0,0,0,.18);
}

html[data-theme="win_classic"] .externalImagePreviewPath,
html[data-theme="win_classic"] .externalImagePreviewInfo{
    color:#4d5662;
}

html[data-theme="win_classic"] .externalImagePreviewInfo{
    background:#e9edf2;
    border-bottom-color:rgba(0,0,0,.14);
}

html[data-theme="win_classic"] .externalImagePreviewBody{
    background:#d8d8d8;
}

@media (max-width:720px){
    .externalImagePreviewCard{
        width:calc(100vw - 20px);
        height:calc(100vh - 20px);
        top:10px;
    }
}
        `;
        document.head.appendChild(style);
    }

    function makeButton(text, className = "btn secondary") {
        const b = document.createElement("button");
        b.type = "button";
        b.className = className;
        b.textContent = text;
        return b;
    }

    function ensureDom() {
        if (state.root) return;

        injectStyles();

        const root = document.createElement("div");
        root.className = "externalImagePreviewOverlay";
        root.setAttribute("aria-hidden", "true");

        root.innerHTML = `
            <div class="externalImagePreviewCard" role="dialog" aria-modal="true" aria-label="Image preview">
                <div class="externalImagePreviewHead">
                    <div>
                        <div class="externalImagePreviewTitle">Image preview</div>
                        <div class="externalImagePreviewPath mono">/</div>
                    </div>
                    <div class="externalImagePreviewActions"></div>
                </div>
                <div class="externalImagePreviewInfo">Loading…</div>
                <div class="externalImagePreviewBody">
                    <img class="externalImagePreviewImg" alt="">
                </div>
            </div>
        `;

        document.body.appendChild(root);

        state.root = root;
        state.card = root.querySelector(".externalImagePreviewCard");
        state.head = root.querySelector(".externalImagePreviewHead");
        state.title = root.querySelector(".externalImagePreviewTitle");
        state.path = root.querySelector(".externalImagePreviewPath");
        state.info = root.querySelector(".externalImagePreviewInfo");
        state.img = root.querySelector(".externalImagePreviewImg");

        const actions = root.querySelector(".externalImagePreviewActions");
        state.prevBtn = makeButton("‹");
        state.nextBtn = makeButton("›");
        state.fitBtn = makeButton("Fit");
        state.actualBtn = makeButton("Actual");
        state.openBtn = makeButton("Open original");
        const closeBtn = makeButton("Close");

        state.prevBtn.title = "Previous image";
        state.nextBtn.title = "Next image";
        state.fitBtn.title = "Fit image to window";
        state.actualBtn.title = "Show actual image size";
        state.openBtn.title = "Open original image in new tab";

        actions.appendChild(state.prevBtn);
        actions.appendChild(state.nextBtn);
        actions.appendChild(state.fitBtn);
        actions.appendChild(state.actualBtn);
        actions.appendChild(state.openBtn);
        actions.appendChild(closeBtn);

        closeBtn.addEventListener("click", closePreview);
        state.prevBtn.addEventListener("click", openPrev);
        state.nextBtn.addEventListener("click", openNext);
        state.fitBtn.addEventListener("click", () => setMode("fit"));
        state.actualBtn.addEventListener("click", () => setMode("actual"));
        state.openBtn.addEventListener("click", () => {
            if (!state.relPath) return;
            window.open(imageUrl(state.relPath), "_blank", "noopener");
        });

        root.addEventListener("click", (ev) => {
            if (state.moved) {
                state.moved = false;
                return;
            }
            if (ev.target === root) closePreview();
        });

        state.head.addEventListener("pointerdown", beginDrag);
        state.head.addEventListener("pointermove", moveDrag);
        state.head.addEventListener("pointerup", endDrag);
        state.head.addEventListener("pointercancel", endDrag);

        document.addEventListener("keydown", (ev) => {
            if (!state.root || !state.root.classList.contains("show")) return;

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
            if (state.root && state.root.classList.contains("show")) {
                clampIntoViewport();
            }
        });
    }

    function setMode(mode) {
        state.mode = mode === "actual" ? "actual" : "fit";
        if (!state.img) return;
        state.img.classList.toggle("actual", state.mode === "actual");
        if (state.fitBtn) state.fitBtn.classList.toggle("active", state.mode === "fit");
        if (state.actualBtn) state.actualBtn.classList.toggle("active", state.mode === "actual");
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
        state.card.style.top = "42px";
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

    function openPreview(item) {
        if (!item || !item.rel) return;

        ensureDom();

        state.relPath = normalizeRelPath(item.rel);

        if (state.title) state.title.textContent = "Image preview";
        if (state.path) state.path.textContent = "/" + state.relPath;
        if (state.info) state.info.textContent = "Loading…";

        if (state.img) {
            state.img.removeAttribute("src");
            state.img.alt = item.name || basenameFromPath(state.relPath) || "image";

            state.img.onload = () => {
                const { items, idx } = currentIndex();
                const pos = idx >= 0 && items.length > 1 ? ` • ${idx + 1} / ${items.length}` : "";
                if (state.info) {
                    state.info.textContent = `${state.img.naturalWidth} × ${state.img.naturalHeight}${pos}`;
                }
                updateNavButtons();
            };

            state.img.onerror = () => {
                if (state.info) state.info.textContent = "Failed to load image preview.";
            };

            state.img.src = imageUrl(state.relPath);
        }

        setMode("fit");
        placeCentered();
        state.root.classList.add("show");
        state.root.setAttribute("aria-hidden", "false");
        document.body.classList.add("externalImagePreviewOpen");
        updateNavButtons();
    }

    function closePreview() {
        if (!state.root) return;
        state.root.classList.remove("show");
        state.root.setAttribute("aria-hidden", "true");
        document.body.classList.remove("externalImagePreviewOpen");

        if (state.img) {
            state.img.removeAttribute("src");
            state.img.alt = "";
        }

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
        state.moved = false;

        state.card.classList.add("dragging");
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
        if (Math.abs(dx) > 2 || Math.abs(dy) > 2) state.moved = true;

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

    function pointerInsidePreview(ev) {
        if (!state.root || !state.root.classList.contains("show") || !state.card) return false;
        const r = state.card.getBoundingClientRect();
        return ev.clientX >= r.left && ev.clientX <= r.right &&
            ev.clientY >= r.top && ev.clientY <= r.bottom;
    }
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

    window.PQNAS_EXTERNAL_IMAGE_PREVIEW = {
        open: openPreview,
        isImageName
    };
})();


