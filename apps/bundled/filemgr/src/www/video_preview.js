window.PQNAS_FILEMGR = window.PQNAS_FILEMGR || {};

(() => {
    "use strict";

    const FM = window.PQNAS_FILEMGR;

    let modal = null;
    let titleEl = null;
    let pathEl = null;
    let videoEl = null;
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

    const VIDEO_EXTS = new Set([
        "mp4",
        "webm",
        "ogv",
        "ogg",
        "mov",
        "m4v"
    ]);

    function fileExtLower(name) {
        const n = String(name || "").toLowerCase().trim();
        const slash = Math.max(n.lastIndexOf("/"), n.lastIndexOf("\\"));
        const base = slash >= 0 ? n.slice(slash + 1) : n;
        const dot = base.lastIndexOf(".");
        if (dot <= 0 || dot === base.length - 1) return "";
        return base.slice(dot + 1);
    }

    function mimeForExt(ext) {
        const e = String(ext || "").toLowerCase();

        if (e === "mp4" || e === "m4v") return "video/mp4";
        if (e === "webm") return "video/webm";
        if (e === "ogv" || e === "ogg") return "video/ogg";
        if (e === "mov") return "video/quicktime";

        return "video/mp4";
    }

    function canOpenFor(item) {
        if (!item || item.type !== "file") return false;
        return VIDEO_EXTS.has(fileExtLower(item.name));
    }

    function safeName(item) {
        return String(item && item.name ? item.name : "Video preview");
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

        const head = modal.querySelector(".videoPreviewHead");
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
        modal.id = "videoPreviewModal";
        modal.className = "videoPreviewModal";
        modal.setAttribute("aria-hidden", "true");

        modal.innerHTML = `
      <div class="videoPreviewBox" role="dialog" aria-modal="false" aria-label="Video preview">
        <div class="videoPreviewHead">
          <div class="videoPreviewTitleWrap">
            <div id="videoPreviewTitle" class="videoPreviewTitle">Video preview</div>
            <div id="videoPreviewPath" class="videoPreviewPath mono"></div>
          </div>
          <div class="videoPreviewActions">
            <button id="videoPreviewOpenOriginal" type="button" class="btn secondary">Open original</button>
            <button id="videoPreviewDownload" type="button" class="btn secondary">Download</button>
            <button id="videoPreviewClose" type="button" class="btn secondary">Close</button>
          </div>
        </div>
        <div class="videoPreviewBody">
          <video
            id="videoPreviewPlayer"
            class="videoPreviewPlayer"
            controls
            playsinline
            preload="metadata"
          ></video>
        </div>
      </div>
    `;

        document.body.appendChild(modal);

        titleEl = modal.querySelector("#videoPreviewTitle");
        pathEl = modal.querySelector("#videoPreviewPath");
        videoEl = modal.querySelector("#videoPreviewPlayer");
        openOriginalBtn = modal.querySelector("#videoPreviewOpenOriginal");
        downloadBtn = modal.querySelector("#videoPreviewDownload");

        const closeBtn = modal.querySelector("#videoPreviewClose");

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

    async function open(item) {
        if (!canOpenFor(item)) return;

        ensureModal();
        placeInitialModal();
        keepModalInViewport();

        const seq = ++openSeq;
        const rel = relPathFor(item);
        const url = getUrl(rel);
        const ext = fileExtLower(item.name);
        const mime = mimeForExt(ext);

        revokeCurrentBlobUrl();

        if (titleEl) titleEl.textContent = safeName(item);
        if (pathEl) pathEl.textContent = "/" + rel;

        if (videoEl) {
            try { videoEl.pause(); } catch (_) {}
            videoEl.removeAttribute("src");
            videoEl.load();
        }

        modal.classList.add("show");
        modal.setAttribute("aria-hidden", "false");

        if (FM && typeof FM.setBadge === "function") FM.setBadge("warn", "loading…");
        const status = FM && typeof FM.getStatusEl === "function" ? FM.getStatusEl() : null;
        if (status) status.textContent = `Loading video preview: ${safeName(item)}…`;

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
                    "Accept": `${mime},video/*,*/*`
                }
            });

            if (!r.ok) {
                throw new Error(`HTTP ${r.status}`);
            }

            const blob = await r.blob();

            if (seq !== openSeq) return;

            const videoBlob = blob.type && blob.type.startsWith("video/")
                ? blob
                : new Blob([blob], { type: mime });

            const blobUrl = URL.createObjectURL(videoBlob);
            currentBlobUrl = blobUrl;

            if (videoEl) {
                videoEl.src = blobUrl;
                videoEl.load();
            }

            if (FM && typeof FM.setBadge === "function") FM.setBadge("ok", "preview");
            if (status) status.textContent = `Previewing video: ${safeName(item)}`;
        } catch (e) {
            if (seq !== openSeq) return;

            if (FM && typeof FM.setBadge === "function") FM.setBadge("err", "error");
            if (status) {
                status.textContent = `Video preview failed: ${String(e && e.message ? e.message : e)}`;
            }

            if (videoEl) {
                try { videoEl.pause(); } catch (_) {}
                videoEl.removeAttribute("src");
                videoEl.load();
            }
        }
    }

    function close() {
        openSeq++;

        if (!modal) return;

        modal.classList.remove("show");
        modal.setAttribute("aria-hidden", "true");

        if (videoEl) {
            try { videoEl.pause(); } catch (_) {}
            videoEl.removeAttribute("src");
            videoEl.load();
        }

        revokeCurrentBlobUrl();
    }

    FM.videoPreview = {
        open,
        close,
        canOpenFor
    };
})();