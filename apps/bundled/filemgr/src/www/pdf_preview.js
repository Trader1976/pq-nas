window.PQNAS_FILEMGR = window.PQNAS_FILEMGR || {};

(() => {
    "use strict";

    const FM = window.PQNAS_FILEMGR;

    let modal = null;
    let titleEl = null;
    let pathEl = null;
    let frameEl = null;
    let openOriginalBtn = null;
    let downloadBtn = null;
    let currentBlobUrl = "";
    let openSeq = 0;
    let dragOn = false;
    let dragStartX = 0;
    let dragStartY = 0;
    let modalStartLeft = 0;
    let modalStartTop = 0;
    let positionedOnce = false;

    function ensureModal() {
        if (modal) return modal;

        modal = document.createElement("div");
        modal.id = "pdfPreviewModal";
        modal.className = "pdfPreviewModal";
        modal.setAttribute("aria-hidden", "true");

        modal.innerHTML = `
      <div class="pdfPreviewBox" role="dialog" aria-modal="true" aria-label="PDF preview">
        <div class="pdfPreviewHead">
          <div class="pdfPreviewTitleWrap">
            <div id="pdfPreviewTitle" class="pdfPreviewTitle">PDF preview</div>
            <div id="pdfPreviewPath" class="pdfPreviewPath mono"></div>
          </div>
          <div class="pdfPreviewActions">
            <button id="pdfPreviewOpenOriginal" type="button" class="btn secondary">Open original</button>
            <button id="pdfPreviewDownload" type="button" class="btn secondary">Download</button>
            <button id="pdfPreviewClose" type="button" class="btn secondary">Close</button>
          </div>
        </div>
        <iframe
          id="pdfPreviewFrame"
          class="pdfPreviewFrame"
          title="PDF preview"
          referrerpolicy="same-origin"
        ></iframe>
      </div>
    `;

        document.body.appendChild(modal);
        installDragging();

        titleEl = modal.querySelector("#pdfPreviewTitle");
        pathEl = modal.querySelector("#pdfPreviewPath");
        frameEl = modal.querySelector("#pdfPreviewFrame");
        openOriginalBtn = modal.querySelector("#pdfPreviewOpenOriginal");
        downloadBtn = modal.querySelector("#pdfPreviewDownload");

        const closeBtn = modal.querySelector("#pdfPreviewClose");

        closeBtn?.addEventListener("click", close);

        modal.addEventListener("click", (e) => {
            if (e.target === modal) close();
        });

        document.addEventListener("keydown", (e) => {
            if (e.key === "Escape" && modal.classList.contains("show")) {
                e.preventDefault();
                close();
            }
        });

        return modal;
    }
    function clamp(n, lo, hi) {
        return Math.max(lo, Math.min(hi, n));
    }

    function placeInitialModal() {
        if (!modal || positionedOnce) return;

        modal.style.left = "50%";
        modal.style.top = "52%";
        modal.style.transform = "translate(-50%, -50%)";
        positionedOnce = true;
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

    function installDragging() {
        if (!modal) return;

        const head = modal.querySelector(".pdfPreviewHead");
        if (!head) return;

        head.addEventListener("pointerdown", (e) => {
            if (e.button !== 0) return;
            if (e.target && e.target.closest && e.target.closest("button")) return;

            detachModalPosition();

            const r = modal.getBoundingClientRect();

            dragOn = true;
            dragStartX = e.clientX;
            dragStartY = e.clientY;
            modalStartLeft = r.left;
            modalStartTop = r.top;

            modal.classList.add("dragging");

            try { head.setPointerCapture(e.pointerId); } catch (_) {}
            e.preventDefault();
        });

        head.addEventListener("pointermove", (e) => {
            if (!dragOn) return;

            const dx = e.clientX - dragStartX;
            const dy = e.clientY - dragStartY;

            const r = modal.getBoundingClientRect();
            const pad = 8;

            const nextLeft = clamp(
                modalStartLeft + dx,
                pad,
                Math.max(pad, window.innerWidth - r.width - pad)
            );

            const nextTop = clamp(
                modalStartTop + dy,
                pad,
                Math.max(pad, window.innerHeight - r.height - pad)
            );

            modal.style.left = `${nextLeft}px`;
            modal.style.top = `${nextTop}px`;
            modal.style.transform = "none";
        });

        const stopDrag = () => {
            if (!dragOn) return;
            dragOn = false;
            modal.classList.remove("dragging");
            keepModalInViewport();
        };

        head.addEventListener("pointerup", stopDrag);
        head.addEventListener("pointercancel", stopDrag);

        window.addEventListener("resize", keepModalInViewport);
    }
    function revokeCurrentBlobUrl() {
        if (!currentBlobUrl) return;
        try { URL.revokeObjectURL(currentBlobUrl); } catch (_) {}
        currentBlobUrl = "";
    }
    function safeName(item) {
        return String(item && item.name ? item.name : "PDF preview");
    }

    function relPathFor(item) {
        if (FM && typeof FM.currentRelPathFor === "function") {
            return FM.currentRelPathFor(item);
        }

        const cur = FM && typeof FM.getCurPath === "function" ? FM.getCurPath() : "";
        const name = safeName(item);
        return cur ? `${cur}/${name}` : name;
    }

    function getUrl(rel) {
        if (FM && typeof FM.apiGetUrl === "function") {
            return FM.apiGetUrl(rel);
        }

        return `/api/v4/files/get?path=${encodeURIComponent(rel || "")}`;
    }

    async function open(item) {
        if (!item || item.type === "dir") return;

        ensureModal();
        placeInitialModal();
        keepModalInViewport();

        const seq = ++openSeq;
        const rel = relPathFor(item);
        const url = getUrl(rel);

        revokeCurrentBlobUrl();

        if (titleEl) titleEl.textContent = safeName(item);
        if (pathEl) pathEl.textContent = "/" + rel;

        if (frameEl) frameEl.src = "about:blank";

        modal.classList.add("show");
        modal.setAttribute("aria-hidden", "false");

        if (FM && typeof FM.setBadge === "function") FM.setBadge("warn", "loading…");
        const status = FM && typeof FM.getStatusEl === "function" ? FM.getStatusEl() : null;
        if (status) status.textContent = `Loading PDF preview: ${safeName(item)}…`;

        if (openOriginalBtn) {
            openOriginalBtn.onclick = () => {
                window.open(url, "_blank", "noopener");
            };
        }

        if (downloadBtn) {
            downloadBtn.onclick = () => {
                window.location.href = url;
            };
        }

        try {
            const r = await fetch(url, {
                method: "GET",
                credentials: "include",
                cache: "no-store",
                headers: {
                    "Accept": "application/pdf,*/*"
                }
            });

            if (!r.ok) {
                throw new Error(`HTTP ${r.status}`);
            }

            const blob = await r.blob();

            if (seq !== openSeq) return;

            const pdfBlob = blob.type === "application/pdf"
                ? blob
                : new Blob([blob], { type: "application/pdf" });

            const blobUrl = URL.createObjectURL(pdfBlob);
            currentBlobUrl = blobUrl;

            if (frameEl) frameEl.src = blobUrl;

            if (FM && typeof FM.setBadge === "function") FM.setBadge("ok", "preview");
            if (status) status.textContent = `Previewing PDF: ${safeName(item)}`;
        } catch (e) {
            if (seq !== openSeq) return;

            if (FM && typeof FM.setBadge === "function") FM.setBadge("err", "error");
            if (status) {
                status.textContent = `PDF preview failed: ${String(e && e.message ? e.message : e)}`;
            }

            if (frameEl) {
                frameEl.src = "about:blank";
            }
        }
    }

    function close() {
        openSeq++;

        if (!modal) return;

        modal.classList.remove("show");
        modal.setAttribute("aria-hidden", "true");

        if (frameEl) frameEl.src = "about:blank";
        revokeCurrentBlobUrl();
    }

    function canOpenFor(item) {
        if (!item || item.type !== "file") return false;
        return /\.pdf$/i.test(String(item.name || ""));
    }

    FM.pdfPreview = {
        open,
        close,
        canOpenFor
    };
})();