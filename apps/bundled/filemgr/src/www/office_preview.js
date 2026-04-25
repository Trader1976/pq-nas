window.PQNAS_FILEMGR = window.PQNAS_FILEMGR || {};

(() => {
    "use strict";

    const FM = window.PQNAS_FILEMGR;

    let modal = null;
    let titleEl = null;
    let pathEl = null;
    let frameEl = null;
    let downloadOriginalBtn = null;

    let currentBlobUrl = "";
    let openSeq = 0;

    let dragOn = false;
    let dragStartX = 0;
    let dragStartY = 0;
    let modalStartLeft = 0;
    let modalStartTop = 0;
    let positionedOnce = false;

    const OFFICE_EXTS = new Set([
        "doc", "docx",
        "xls", "xlsx",
        "ppt", "pptx",
        "odt", "ods", "odp",
        "rtf"
    ]);

    function fileExtLower(name) {
        const n = String(name || "").toLowerCase().trim();
        const slash = Math.max(n.lastIndexOf("/"), n.lastIndexOf("\\"));
        const base = slash >= 0 ? n.slice(slash + 1) : n;
        const dot = base.lastIndexOf(".");
        if (dot <= 0 || dot === base.length - 1) return "";
        return base.slice(dot + 1);
    }

    function canOpenFor(item) {
        if (!item || item.type !== "file") return false;
        return OFFICE_EXTS.has(fileExtLower(item.name));
    }

    function safeName(item) {
        return String(item && item.name ? item.name : "Office preview");
    }

    function relPathFor(item) {
        if (FM && typeof FM.currentRelPathFor === "function") {
            return FM.currentRelPathFor(item);
        }

        const cur = FM && typeof FM.getCurPath === "function" ? FM.getCurPath() : "";
        const name = safeName(item);
        return cur ? `${cur}/${name}` : name;
    }

    function getDownloadUrl(rel) {
        if (FM && typeof FM.apiGetUrl === "function") {
            return FM.apiGetUrl(rel);
        }

        return `/api/v4/files/get?path=${encodeURIComponent(rel || "")}`;
    }

    function getPreviewUrl(rel) {
        return `/api/v4/files/office_preview?path=${encodeURIComponent(rel || "")}`;
    }

    function revokeCurrentBlobUrl() {
        if (!currentBlobUrl) return;
        try { URL.revokeObjectURL(currentBlobUrl); } catch (_) {}
        currentBlobUrl = "";
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

        const head = modal.querySelector(".officePreviewHead");
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

    function ensureModal() {
        if (modal) return modal;

        modal = document.createElement("div");
        modal.id = "officePreviewModal";
        modal.className = "officePreviewModal";
        modal.setAttribute("aria-hidden", "true");

        modal.innerHTML = `
      <div class="officePreviewBox" role="dialog" aria-modal="false" aria-label="Office document preview">
        <div class="officePreviewHead">
          <div class="officePreviewTitleWrap">
            <div id="officePreviewTitle" class="officePreviewTitle">Office preview</div>
            <div id="officePreviewPath" class="officePreviewPath mono"></div>
          </div>
          <div class="officePreviewActions">
            <button id="officePreviewDownloadOriginal" type="button" class="btn secondary">Download original</button>
            <button id="officePreviewClose" type="button" class="btn secondary">Close</button>
          </div>
        </div>

        <div id="officePreviewLoading" class="officePreviewLoading">
          Converting document to PDF…
        </div>

        <iframe
          id="officePreviewFrame"
          class="officePreviewFrame"
          title="Office document preview"
          referrerpolicy="same-origin"
        ></iframe>
      </div>
    `;

        document.body.appendChild(modal);

        titleEl = modal.querySelector("#officePreviewTitle");
        pathEl = modal.querySelector("#officePreviewPath");
        frameEl = modal.querySelector("#officePreviewFrame");
        downloadOriginalBtn = modal.querySelector("#officePreviewDownloadOriginal");

        const closeBtn = modal.querySelector("#officePreviewClose");

        closeBtn?.addEventListener("click", close);

        document.addEventListener("keydown", (e) => {
            if (e.key === "Escape" && modal.classList.contains("show")) {
                e.preventDefault();
                close();
            }
        });

        installDragging();

        return modal;
    }

    function setLoading(on, text) {
        const loading = modal ? modal.querySelector("#officePreviewLoading") : null;
        if (!loading) return;

        loading.classList.toggle("hidden", !on);
        loading.textContent = text || "Converting document to PDF…";
    }

    async function open(item) {
        if (!canOpenFor(item)) return;

        ensureModal();
        placeInitialModal();
        keepModalInViewport();

        const seq = ++openSeq;
        const rel = relPathFor(item);
        const previewUrl = getPreviewUrl(rel);
        const downloadUrl = getDownloadUrl(rel);

        revokeCurrentBlobUrl();

        if (titleEl) titleEl.textContent = safeName(item);
        if (pathEl) pathEl.textContent = "/" + rel;

        if (frameEl) frameEl.src = "about:blank";

        modal.classList.add("show");
        modal.setAttribute("aria-hidden", "false");
        setLoading(true, "Converting document to PDF…");

        if (downloadOriginalBtn) {
            downloadOriginalBtn.onclick = () => {
                window.location.href = downloadUrl;
            };
        }

        if (FM && typeof FM.setBadge === "function") FM.setBadge("warn", "converting…");
        const status = FM && typeof FM.getStatusEl === "function" ? FM.getStatusEl() : null;
        if (status) status.textContent = `Converting document preview: ${safeName(item)}…`;

        try {
            const r = await fetch(previewUrl, {
                method: "GET",
                credentials: "include",
                cache: "no-store",
                headers: {
                    "Accept": "application/pdf,*/*"
                }
            });

            if (!r.ok) {
                let msg = `HTTP ${r.status}`;
                const j = await r.json().catch(() => null);
                if (j && (j.message || j.error || j.detail)) {
                    msg = [j.error, j.message, j.detail].filter(Boolean).join(" ");
                }
                throw new Error(msg);
            }

            const blob = await r.blob();

            if (seq !== openSeq) return;

            const pdfBlob = blob.type === "application/pdf"
                ? blob
                : new Blob([blob], { type: "application/pdf" });

            const blobUrl = URL.createObjectURL(pdfBlob);
            currentBlobUrl = blobUrl;

            if (frameEl) frameEl.src = blobUrl;
            setLoading(false);

            if (FM && typeof FM.setBadge === "function") FM.setBadge("ok", "preview");
            if (status) status.textContent = `Previewing Office document: ${safeName(item)}`;
        } catch (e) {
            if (seq !== openSeq) return;

            if (frameEl) frameEl.src = "about:blank";
            setLoading(false);

            close();

            if (FM && typeof FM.setBadge === "function") FM.setBadge("ok", "download");
            if (status) status.textContent = `Office preview unavailable. Downloading: ${safeName(item)}`;

            window.location.href = downloadUrl;
        }
    }

    function close() {
        openSeq++;

        if (!modal) return;

        modal.classList.remove("show");
        modal.setAttribute("aria-hidden", "true");

        if (frameEl) frameEl.src = "about:blank";
        setLoading(false);
        revokeCurrentBlobUrl();
    }

    FM.officePreview = {
        open,
        close,
        canOpenFor
    };
})();