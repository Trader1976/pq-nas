window.PQNAS_FILEMGR = window.PQNAS_FILEMGR || {};

(() => {
    "use strict";

    const FM = window.PQNAS_FILEMGR;

    let modal = null;
    let titleEl = null;
    let pathEl = null;
    let audioEl = null;
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

    const AUDIO_EXTS = new Set([
        "mp3",
        "wav",
        "ogg",
        "oga",
        "m4a",
        "aac",
        "flac",
        "opus"
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

        if (e === "mp3") return "audio/mpeg";
        if (e === "wav") return "audio/wav";
        if (e === "ogg" || e === "oga") return "audio/ogg";
        if (e === "m4a") return "audio/mp4";
        if (e === "aac") return "audio/aac";
        if (e === "flac") return "audio/flac";
        if (e === "opus") return "audio/ogg";

        return "audio/mpeg";
    }

    function canOpenFor(item) {
        if (!item || item.type !== "file") return false;
        return AUDIO_EXTS.has(fileExtLower(item.name));
    }

    function safeName(item) {
        return String(item && item.name ? item.name : "Audio preview");
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

        const head = modal.querySelector(".audioPreviewHead");
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
        modal.id = "audioPreviewModal";
        modal.className = "audioPreviewModal";
        modal.setAttribute("aria-hidden", "true");

        modal.innerHTML = `
      <div class="audioPreviewBox" role="dialog" aria-modal="false" aria-label="Audio preview">
        <div class="audioPreviewHead">
          <div class="audioPreviewTitleWrap">
            <div id="audioPreviewTitle" class="audioPreviewTitle">Audio preview</div>
            <div id="audioPreviewPath" class="audioPreviewPath mono"></div>
          </div>
          <div class="audioPreviewActions">
            <button id="audioPreviewOpenOriginal" type="button" class="btn secondary">Open original</button>
            <button id="audioPreviewDownload" type="button" class="btn secondary">Download</button>
            <button id="audioPreviewClose" type="button" class="btn secondary">Close</button>
          </div>
        </div>

        <div class="audioPreviewBody">
          <div class="audioPreviewIcon" aria-hidden="true">♪</div>
          <div class="audioPreviewNow">
            <div id="audioPreviewNowTitle" class="audioPreviewNowTitle"></div>
            <div class="audioPreviewHint">Browser-native audio playback</div>
          </div>
          <audio
            id="audioPreviewPlayer"
            class="audioPreviewPlayer"
            controls
            preload="metadata"
          ></audio>
        </div>
      </div>
    `;

        document.body.appendChild(modal);

        titleEl = modal.querySelector("#audioPreviewTitle");
        pathEl = modal.querySelector("#audioPreviewPath");
        audioEl = modal.querySelector("#audioPreviewPlayer");
        openOriginalBtn = modal.querySelector("#audioPreviewOpenOriginal");
        downloadBtn = modal.querySelector("#audioPreviewDownload");

        const closeBtn = modal.querySelector("#audioPreviewClose");
        const nowTitle = modal.querySelector("#audioPreviewNowTitle");

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

        const nowTitle = modal ? modal.querySelector("#audioPreviewNowTitle") : null;
        if (nowTitle) nowTitle.textContent = safeName(item);

        if (audioEl) {
            try { audioEl.pause(); } catch (_) {}
            audioEl.removeAttribute("src");
            audioEl.load();
        }

        modal.classList.add("show");
        modal.setAttribute("aria-hidden", "false");

        if (FM && typeof FM.setBadge === "function") FM.setBadge("warn", "loading…");
        const status = FM && typeof FM.getStatusEl === "function" ? FM.getStatusEl() : null;
        if (status) status.textContent = `Loading audio preview: ${safeName(item)}…`;

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
                    "Accept": `${mime},audio/*,*/*`
                }
            });

            if (!r.ok) {
                throw new Error(`HTTP ${r.status}`);
            }

            const blob = await r.blob();

            if (seq !== openSeq) return;

            const audioBlob = blob.type && blob.type.startsWith("audio/")
                ? blob
                : new Blob([blob], { type: mime });

            const blobUrl = URL.createObjectURL(audioBlob);
            currentBlobUrl = blobUrl;

            if (audioEl) {
                audioEl.src = blobUrl;
                audioEl.load();
            }

            if (FM && typeof FM.setBadge === "function") FM.setBadge("ok", "preview");
            if (status) status.textContent = `Previewing audio: ${safeName(item)}`;
        } catch (e) {
            if (seq !== openSeq) return;

            if (FM && typeof FM.setBadge === "function") FM.setBadge("err", "error");
            if (status) {
                status.textContent = `Audio preview failed: ${String(e && e.message ? e.message : e)}`;
            }

            if (audioEl) {
                try { audioEl.pause(); } catch (_) {}
                audioEl.removeAttribute("src");
                audioEl.load();
            }
        }
    }

    function close() {
        openSeq++;

        if (!modal) return;

        modal.classList.remove("show");
        modal.setAttribute("aria-hidden", "true");

        if (audioEl) {
            try { audioEl.pause(); } catch (_) {}
            audioEl.removeAttribute("src");
            audioEl.load();
        }

        revokeCurrentBlobUrl();
    }

    FM.audioPreview = {
        open,
        close,
        canOpenFor
    };
})();