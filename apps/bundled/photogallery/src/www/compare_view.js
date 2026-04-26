(() => {
    "use strict";

    window.PQNAS_PHOTOGALLERY = window.PQNAS_PHOTOGALLERY || {};

    let modal = null;
    let imgA = null;
    let imgB = null;
    let titleA = null;
    let titleB = null;
    let zoomLabel = null;

    const state = {
        paths: [],
        zoom: 1,
        panX: 0,
        panY: 0,
        dragging: false,
        dragStartX: 0,
        dragStartY: 0,
        startPanX: 0,
        startPanY: 0
    };

    const winDrag = {
        active: false,
        startX: 0,
        startY: 0,
        modalLeft: 0,
        modalTop: 0,
        positionedOnce: false
    };

    function fileGetUrl(relPath) {
        return `/api/v4/files/get?path=${encodeURIComponent(relPath || "")}`;
    }

    function baseName(path) {
        const p = String(path || "");
        const i = p.lastIndexOf("/");
        return i >= 0 ? p.slice(i + 1) : p;
    }

    function clamp(n, lo, hi) {
        return Math.max(lo, Math.min(hi, n));
    }
    function placeInitialModal() {
        if (!modal || winDrag.positionedOnce) return;

        modal.style.left = "50%";
        modal.style.top = "52%";
        modal.style.transform = "translate(-50%, -50%)";
        winDrag.positionedOnce = true;
    }

    function detachModalPosition() {
        if (!modal) return;

        const r = modal.getBoundingClientRect();
        modal.style.left = `${r.left}px`;
        modal.style.top = `${r.top}px`;
        modal.style.transform = "none";
    }

    function keepModalInViewport() {
        if (!modal) return;

        const r = modal.getBoundingClientRect();
        const pad = 8;

        const left = clamp(r.left, pad, Math.max(pad, window.innerWidth - r.width - pad));
        const top = clamp(r.top, pad, Math.max(pad, window.innerHeight - r.height - pad));

        modal.style.left = `${left}px`;
        modal.style.top = `${top}px`;
        modal.style.transform = "none";
    }

    function installWindowDragging() {
        if (!modal) return;

        const head = modal.querySelector(".compareViewHead");
        if (!head) return;

        head.addEventListener("pointerdown", (e) => {
            if (e.button !== 0) return;
            if (e.target && e.target.closest && e.target.closest("button")) return;

            detachModalPosition();

            const r = modal.getBoundingClientRect();

            winDrag.active = true;
            winDrag.startX = e.clientX;
            winDrag.startY = e.clientY;
            winDrag.modalLeft = r.left;
            winDrag.modalTop = r.top;

            modal.classList.add("windowDragging");

            try { head.setPointerCapture(e.pointerId); } catch (_) {}
            e.preventDefault();
        });

        head.addEventListener("pointermove", (e) => {
            if (!winDrag.active) return;

            const dx = e.clientX - winDrag.startX;
            const dy = e.clientY - winDrag.startY;

            const r = modal.getBoundingClientRect();
            const pad = 8;

            const nextLeft = clamp(
                winDrag.modalLeft + dx,
                pad,
                Math.max(pad, window.innerWidth - r.width - pad)
            );

            const nextTop = clamp(
                winDrag.modalTop + dy,
                pad,
                Math.max(pad, window.innerHeight - r.height - pad)
            );

            modal.style.left = `${nextLeft}px`;
            modal.style.top = `${nextTop}px`;
            modal.style.transform = "none";
        });

        const stop = () => {
            if (!winDrag.active) return;
            winDrag.active = false;
            modal.classList.remove("windowDragging");
            keepModalInViewport();
        };

        head.addEventListener("pointerup", stop);
        head.addEventListener("pointercancel", stop);

        window.addEventListener("resize", keepModalInViewport);
    }
    function applyTransform() {
        const t = `translate(${state.panX}px, ${state.panY}px) scale(${state.zoom})`;

        if (imgA) imgA.style.transform = t;
        if (imgB) imgB.style.transform = t;

        if (zoomLabel) zoomLabel.textContent = `${Math.round(state.zoom * 100)}%`;
    }

    function resetView() {
        state.zoom = 1;
        state.panX = 0;
        state.panY = 0;
        applyTransform();
    }

    function zoomBy(delta, cx, cy) {
        const oldZoom = state.zoom;
        const nextZoom = clamp(oldZoom * delta, 0.1, 8);

        if (Math.abs(nextZoom - oldZoom) < 0.001) return;

        // Keep the point under the cursor roughly stable.
        const rect = modal ? modal.getBoundingClientRect() : null;
        const mx = rect ? cx - rect.left - rect.width / 2 : 0;
        const my = rect ? cy - rect.top - rect.height / 2 : 0;

        const scale = nextZoom / oldZoom;
        state.panX = mx - (mx - state.panX) * scale;
        state.panY = my - (my - state.panY) * scale;
        state.zoom = nextZoom;

        applyTransform();
    }

    function ensureModal() {
        if (modal) return modal;

        modal = document.createElement("div");
        modal.id = "compareViewModal";
        modal.className = "compareViewModal";
        modal.setAttribute("aria-hidden", "true");

        modal.innerHTML = `
            <div class="compareViewCard" role="dialog" aria-modal="false" aria-label="Side by side image comparison">
                <div class="compareViewHead">
                    <div class="compareViewTitle">
                        <strong>Compare side by side</strong>
                        <span id="compareViewZoom" class="compareViewZoom">100%</span>
                    </div>
                    <div class="compareViewActions">
                        <button id="compareViewReset" type="button" class="btn secondary">Reset</button>
                        <button id="compareViewFit" type="button" class="btn secondary">Fit</button>
                        <button id="compareViewClose" type="button" class="btn secondary">Close</button>
                    </div>
                </div>

                <div class="compareViewBody">
                    <div class="comparePane">
                        <div id="compareTitleA" class="comparePaneTitle mono"></div>
                        <div class="compareImageWrap">
                            <img id="compareImgA" class="compareImage" alt="">
                        </div>
                    </div>

                    <div class="comparePane">
                        <div id="compareTitleB" class="comparePaneTitle mono"></div>
                        <div class="compareImageWrap">
                            <img id="compareImgB" class="compareImage" alt="">
                        </div>
                    </div>
                </div>

                <div class="compareViewHint">
                    Mouse wheel zooms both images. Drag pans both images together.
                </div>
            </div>
        `;

        document.body.appendChild(modal);
        installWindowDragging();

        imgA = modal.querySelector("#compareImgA");
        imgB = modal.querySelector("#compareImgB");
        titleA = modal.querySelector("#compareTitleA");
        titleB = modal.querySelector("#compareTitleB");
        zoomLabel = modal.querySelector("#compareViewZoom");

        const closeBtn = modal.querySelector("#compareViewClose");
        const resetBtn = modal.querySelector("#compareViewReset");
        const fitBtn = modal.querySelector("#compareViewFit");
        const body = modal.querySelector(".compareViewBody");

        closeBtn?.addEventListener("click", close);
        resetBtn?.addEventListener("click", resetView);
        fitBtn?.addEventListener("click", resetView);

        document.addEventListener("keydown", (e) => {
            if (e.key === "Escape" && modal.classList.contains("show")) {
                e.preventDefault();
                close();
            }
        });

        body?.addEventListener("wheel", (e) => {
            e.preventDefault();
            const delta = e.deltaY < 0 ? 1.12 : 1 / 1.12;
            zoomBy(delta, e.clientX, e.clientY);
        }, { passive: false });

        body?.addEventListener("pointerdown", (e) => {
            if (e.button !== 0) return;

            state.dragging = true;
            state.dragStartX = e.clientX;
            state.dragStartY = e.clientY;
            state.startPanX = state.panX;
            state.startPanY = state.panY;

            modal.classList.add("dragging");

            try { body.setPointerCapture(e.pointerId); } catch (_) {}
            e.preventDefault();
        });

        body?.addEventListener("pointermove", (e) => {
            if (!state.dragging) return;

            state.panX = state.startPanX + (e.clientX - state.dragStartX);
            state.panY = state.startPanY + (e.clientY - state.dragStartY);

            applyTransform();
        });

        const stopDrag = () => {
            if (!state.dragging) return;
            state.dragging = false;
            modal.classList.remove("dragging");
        };

        body?.addEventListener("pointerup", stopDrag);
        body?.addEventListener("pointercancel", stopDrag);

        return modal;
    }

    function open(paths) {
        const list = Array.isArray(paths) ? paths.map(String).filter(Boolean) : [];
        if (list.length !== 2) return false;

        ensureModal();
        placeInitialModal();
        keepModalInViewport();

        state.paths = list.slice(0, 2);
        resetView();

        if (titleA) titleA.textContent = "/" + state.paths[0];
        if (titleB) titleB.textContent = "/" + state.paths[1];

        if (imgA) {
            imgA.alt = baseName(state.paths[0]);
            imgA.src = fileGetUrl(state.paths[0]);
        }

        if (imgB) {
            imgB.alt = baseName(state.paths[1]);
            imgB.src = fileGetUrl(state.paths[1]);
        }

        modal.classList.add("show");
        modal.setAttribute("aria-hidden", "false");

        return true;
    }

    function close() {
        if (!modal) return;

        modal.classList.remove("show");
        modal.setAttribute("aria-hidden", "true");

        if (imgA) imgA.removeAttribute("src");
        if (imgB) imgB.removeAttribute("src");

        state.paths = [];
        resetView();
    }

    window.PQNAS_PHOTOGALLERY.compareView = {
        open,
        close
    };
})();