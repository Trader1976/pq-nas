(() => {
    "use strict";

    const PG = window.PQNAS_PHOTOGALLERY;
    if (!PG) return;

    const el = (id) => document.getElementById(id);

    const previewModal = el("previewModal");
    const metaModal = el("metaModal");
    const previewImg = el("previewImg");
    const previewSlideMeta = el("previewSlideMeta");
    const previewSlideMetaText = el("previewSlideMetaText");
    const slideshowShowMeta = el("slideshowShowMeta");

    const slideshowBtn = el("slideshowBtn");
    const slideshowModal = el("slideshowModal");
    const slideshowClose = el("slideshowClose");
    const slideshowCount = el("slideshowCount");
    const slideshowSub = el("slideshowSub");
    const slideshowInterval = el("slideshowInterval");
    const slideshowShuffle = el("slideshowShuffle");
    const slideshowLoop = el("slideshowLoop");
    const slideshowFullscreen = el("slideshowFullscreen");
    const slideshowStatus = el("slideshowStatus");
    const slideshowStartBtn = el("slideshowStartBtn");

    const previewFullscreenBtn = el("previewFullscreenBtn");

    const INTERVAL_KEY = "pqnas_photogallery_slideshow_interval_v1";
    const SHUFFLE_KEY = "pqnas_photogallery_slideshow_shuffle_v1";
    const LOOP_KEY = "pqnas_photogallery_slideshow_loop_v1";
    const SHOW_META_KEY = "pqnas_photogallery_slideshow_show_meta_v1";
    const FULLSCREEN_KEY = "pqnas_photogallery_slideshow_fullscreen_v1";

    const ss = {
        playing: false,
        timer: null,
        cursorTimer: null,
        intervalMs: 5000,
        shuffle: false,
        loop: true,
        fullscreen: true,
        showMeta: false,
        items: [],
        index: -1
    };

    function allowedIntervals() {
        return new Set([2000, 3000, 5000, 10000, 15000]);
    }

    function loadPrefs() {
        try {
            const iv = Number(localStorage.getItem(INTERVAL_KEY) || "5000");
            if (allowedIntervals().has(iv)) {
                ss.intervalMs = iv;
            }
        } catch (_) {}

        try {
            ss.shuffle = localStorage.getItem(SHUFFLE_KEY) === "1";
        } catch (_) {
            ss.shuffle = false;
        }

        try {
            const raw = localStorage.getItem(LOOP_KEY);
            ss.loop = raw == null ? true : raw === "1";
        } catch (_) {
            ss.loop = true;
        }

        try {
            const raw = localStorage.getItem(FULLSCREEN_KEY);
            ss.fullscreen = raw == null ? true : raw === "1";
        } catch (_) {
            ss.fullscreen = true;
        }
        try {
            ss.showMeta = localStorage.getItem(SHOW_META_KEY) === "1";
        } catch (_) {
            ss.showMeta = false;
        }
    }

    function savePrefs() {
        try { localStorage.setItem(INTERVAL_KEY, String(ss.intervalMs)); } catch (_) {}
        try { localStorage.setItem(SHUFFLE_KEY, ss.shuffle ? "1" : "0"); } catch (_) {}
        try { localStorage.setItem(LOOP_KEY, ss.loop ? "1" : "0"); } catch (_) {}
        try { localStorage.setItem(FULLSCREEN_KEY, ss.fullscreen ? "1" : "0"); } catch (_) {}
        try { localStorage.setItem(SHOW_META_KEY, ss.showMeta ? "1" : "0"); } catch (_) {}
    }
    function clearCursorTimer() {
        if (ss.cursorTimer) {
            clearTimeout(ss.cursorTimer);
            ss.cursorTimer = null;
        }
    }

    function scheduleCursorHide() {
        clearCursorTimer();
        if (!previewModal) return;
        if (!ss.playing) return;
        if (document.fullscreenElement !== previewModal) return;

        ss.cursorTimer = setTimeout(() => {
            if (ss.playing && document.fullscreenElement === previewModal) {
                previewModal.classList.add("cursorHidden");
            }
        }, 1200);
    }

    function showSlideshowCursor() {
        if (!previewModal) return;
        previewModal.classList.remove("cursorHidden");
        scheduleCursorHide();
    }

    function syncSlideshowFullscreenClass() {
        if (!previewModal) return;

        previewModal.classList.toggle("slideshowFullscreen", ss.playing);
        previewModal.classList.toggle("slideshowPlaying", ss.playing);

        if (!ss.playing) {
            previewModal.classList.remove("cursorHidden");
            previewModal.classList.remove("showSlideMeta");
            clearCursorTimer();
            if (previewImg) previewImg.classList.remove("pgFade");
            updateSlideMetaOverlay();
            return;
        }

        scheduleCursorHide();
        updateSlideMetaOverlay();
    }
    function clearTimer() {
        if (ss.timer) {
            clearTimeout(ss.timer);
            ss.timer = null;
        }
    }

    function currentFilteredItems() {
        return PG.getFilteredImageItems ? PG.getFilteredImageItems() : [];
    }

    function selectedRelPaths() {
        return PG.getSelectedRelPaths ? PG.getSelectedRelPaths() : [];
    }

    function selectedImageItems() {
        const selected = new Set(selectedRelPaths());
        if (selected.size < 2) return [];

        return currentFilteredItems().filter((it) => {
            const rel = PG.currentRelPathFor(it);
            return selected.has(rel);
        });
    }

    function slideshowSource() {
        const selectedItems = selectedImageItems();
        if (selectedItems.length >= 2) {
            return {
                mode: "selection",
                items: selectedItems
            };
        }

        return {
            mode: "view",
            items: currentFilteredItems()
        };
    }

    function currentPreviewPath() {
        return PG.getPreviewPath ? PG.getPreviewPath() : "";
    }

    function currentIndex(items) {
        const cur = currentPreviewPath();
        if (!cur) return -1;
        return items.findIndex((it) => PG.currentRelPathFor(it) === cur);
    }
    function currentItem() {
        if (ss.playing && ss.index >= 0 && ss.index < ss.items.length) {
            return ss.items[ss.index] || null;
        }

        const items = currentFilteredItems();
        const idx = currentIndex(items);
        if (idx < 0 || idx >= items.length) return null;
        return items[idx];
    }

    function currentItemDescription() {
        const item = currentItem();
        if (!item) return "";

        const desc = item.description;

        if (typeof desc === "string") {
            return desc.trim();
        }

        if (desc && typeof desc === "object") {
            const xDefault = String(desc["x-default"] || "").trim();
            if (xDefault) return xDefault;

            for (const v of Object.values(desc)) {
                const s = String(v || "").trim();
                if (s) return s;
            }
        }

        return String(item.notes_text || "").trim();
    }

    function updateSlideMetaOverlay() {
        if (!previewModal || !previewSlideMeta || !previewSlideMetaText) return;

        const text = currentItemDescription();
        const show = !!(ss.playing && ss.showMeta && text);

        previewModal.classList.toggle("showSlideMeta", show);
        previewSlideMetaText.textContent = show ? text : "";
    }
    function isPreviewOpen() {
        return !!(PG.isPreviewOpen && PG.isPreviewOpen());
    }

    function shuffleArray(items) {
        const out = items.slice();
        for (let i = out.length - 1; i > 0; i--) {
            const j = Math.floor(Math.random() * (i + 1));
            const tmp = out[i];
            out[i] = out[j];
            out[j] = tmp;
        }
        return out;
    }

    function applyUi() {
        if (slideshowInterval) slideshowInterval.value = String(ss.intervalMs);
        if (slideshowShuffle) slideshowShuffle.checked = !!ss.shuffle;
        if (slideshowLoop) slideshowLoop.checked = !!ss.loop;
        if (slideshowFullscreen) slideshowFullscreen.checked = !!ss.fullscreen;
        if (slideshowShowMeta) slideshowShowMeta.checked = !!ss.showMeta;

        const source = slideshowSource();
        const canStart = source.items.length >= 2;

        if (slideshowBtn) {
            slideshowBtn.disabled = !canStart && !ss.playing;
            slideshowBtn.title = ss.playing
                ? "Slideshow is running"
                : (canStart ? "Start slideshow" : "Need at least 2 photos");
        }

        if (slideshowStartBtn) {
            slideshowStartBtn.disabled = !canStart;
        }

        if (slideshowCount && slideshowModal && slideshowModal.classList.contains("show")) {
            updateSetupSummary();
        }
    }

    function updateSetupSummary() {
        const source = slideshowSource();
        const selectedCount = selectedRelPaths().length;
        const filteredCount = currentFilteredItems().length;

        if (slideshowCount) {
            slideshowCount.textContent =
                `${source.items.length} photo${source.items.length === 1 ? "" : "s"}`;
        }

        if (slideshowSub) {
            if (source.mode === "selection") {
                slideshowSub.textContent =
                    `Using ${source.items.length} selected photo${source.items.length === 1 ? "" : "s"}`;
            } else if (selectedCount === 1) {
                slideshowSub.textContent =
                    `Using current filtered view (${filteredCount} photo${filteredCount === 1 ? "" : "s"}). One photo is selected, so selection is ignored.`;
            } else {
                slideshowSub.textContent =
                    `Using current filtered view (${filteredCount} photo${filteredCount === 1 ? "" : "s"})`;
            }
        }

        if (slideshowStatus) {
            if (source.items.length >= 2) {
                slideshowStatus.textContent = "Ready.";
            } else if (source.items.length === 1) {
                slideshowStatus.textContent = "Need at least 2 photos for slideshow.";
            } else {
                slideshowStatus.textContent = "No photos available.";
            }
        }
    }

    function openSetupModal() {
        if (!slideshowModal) return;
        updateSetupSummary();
        applyUi();
        slideshowModal.classList.add("show");
        slideshowModal.setAttribute("aria-hidden", "false");
    }

    function closeSetupModal() {
        if (!slideshowModal) return;
        slideshowModal.classList.remove("show");
        slideshowModal.setAttribute("aria-hidden", "true");
    }

    async function requestPreviewFullscreen() {
        if (!previewModal) return;
        if (document.fullscreenElement) return;

        try {
            await previewModal.requestFullscreen();
        } catch (_) {}
    }

    async function togglePreviewFullscreen() {
        try {
            if (document.fullscreenElement) {
                await document.exitFullscreen();
            } else if (previewModal) {
                await previewModal.requestFullscreen();
            }
        } catch (_) {}
    }
    function openPreviewWithFade(item) {
        if (!item) return;

        if (!ss.playing || !previewImg) {
            PG.openPreviewFor(item);
            return;
        }

        previewImg.classList.add("pgFade");

        setTimeout(() => {
            PG.openPreviewFor(item);
        }, 120);
    }
    function stop(reason = "") {
        clearTimer();
        ss.playing = false;
        ss.items = [];
        ss.index = -1;
        syncSlideshowFullscreenClass();
        applyUi();

        if (reason) PG.setStatus?.(reason);
        PG.setBadge?.("ok", "ready");
    }

    function pause(reason = "") {
        if (!ss.playing) return;
        clearTimer();
        ss.playing = false;
        syncSlideshowFullscreenClass();
        applyUi();

        if (reason) PG.setStatus?.(reason);
        PG.setBadge?.("ok", "ready");
    }
    function scheduleNext() {
        clearTimer();
        if (!ss.playing) return;
        if (!ss.items.length) {
            stop("Slideshow finished.");
            return;
        }

        ss.timer = setTimeout(() => {
            advance(+1);
        }, ss.intervalMs);
    }

    function advance(dir) {
        if (!ss.items.length) {
            stop("Slideshow finished.");
            return;
        }

        const nextIdx = ss.index + dir;

        if (nextIdx >= ss.items.length) {
            if (!ss.loop) {
                stop("Slideshow finished.");
                return;
            }
            ss.index = 0;
        } else if (nextIdx < 0) {
            if (!ss.loop) {
                stop("Slideshow finished.");
                return;
            }
            ss.index = ss.items.length - 1;
        } else {
            ss.index = nextIdx;
        }

        const item = ss.items[ss.index];
        if (!item) {
            stop("Slideshow finished.");
            return;
        }

        openPreviewWithFade(item);
        scheduleNext();
    }

    async function start() {
        const source = slideshowSource();
        if (source.items.length < 2) {
            updateSetupSummary();
            applyUi();
            return;
        }

        ss.intervalMs = Number(slideshowInterval?.value || "5000");
        if (!allowedIntervals().has(ss.intervalMs)) {
            ss.intervalMs = 5000;
        }

        ss.shuffle = !!(slideshowShuffle && slideshowShuffle.checked);
        ss.loop = !!(slideshowLoop && slideshowLoop.checked);
        ss.fullscreen = !!(slideshowFullscreen && slideshowFullscreen.checked);
        ss.showMeta = !!(slideshowShowMeta && slideshowShowMeta.checked);
        savePrefs();

        const baseItems = ss.shuffle ? shuffleArray(source.items) : source.items.slice();
        const curPath = currentPreviewPath();

        ss.items = baseItems;
        ss.index = 0;

        if (curPath) {
            const idx = ss.items.findIndex((it) => PG.currentRelPathFor(it) === curPath);
            if (idx >= 0) ss.index = idx;
        }

        ss.playing = true;
        closeSetupModal();
        syncSlideshowFullscreenClass();
        updateSlideMetaOverlay();
        applyUi();

        PG.setBadge?.("warn", "slideshow");
        PG.setStatus?.(
            `Slideshow running • ${Math.round(ss.intervalMs / 1000)}s` +
            (ss.shuffle ? " • shuffle" : "") +
            (ss.loop ? " • loop" : "")
        );

        PG.openPreviewFor(ss.items[ss.index]);

        if (ss.fullscreen) {
            await requestPreviewFullscreen();
        }

        scheduleNext();
    }

    slideshowBtn?.addEventListener("click", openSetupModal);
    slideshowClose?.addEventListener("click", closeSetupModal);
    slideshowModal?.addEventListener("click", (e) => {
        if (e.target === slideshowModal) closeSetupModal();
    });
    slideshowStartBtn?.addEventListener("click", start);

    slideshowInterval?.addEventListener("change", () => {
        const v = Number(slideshowInterval.value || "5000");
        if (!allowedIntervals().has(v)) return;
        ss.intervalMs = v;
        savePrefs();
        applyUi();
    });

    slideshowShuffle?.addEventListener("change", () => {
        ss.shuffle = !!slideshowShuffle.checked;
        savePrefs();
        applyUi();
    });

    slideshowLoop?.addEventListener("change", () => {
        ss.loop = !!slideshowLoop.checked;
        savePrefs();
        applyUi();
    });

    slideshowShowMeta?.addEventListener("change", () => {
        ss.showMeta = !!slideshowShowMeta.checked;
        savePrefs();
        applyUi();
        updateSlideMetaOverlay();
    });

    slideshowFullscreen?.addEventListener("change", () => {
        ss.fullscreen = !!slideshowFullscreen.checked;
        savePrefs();
        applyUi();
    });

    previewFullscreenBtn?.addEventListener("click", togglePreviewFullscreen);

    previewImg?.addEventListener("load", () => {
        if (!previewImg) return;

        requestAnimationFrame(() => {
            previewImg.classList.remove("pgFade");
            updateSlideMetaOverlay();
        });
    });

    previewModal?.addEventListener("mousemove", () => {
        if (ss.playing) showSlideshowCursor();
    });

    previewModal?.addEventListener("mousedown", () => {
        if (ss.playing) showSlideshowCursor();
    });

    previewModal?.addEventListener("touchstart", () => {
        if (ss.playing) showSlideshowCursor();
    }, { passive: true });

    document.addEventListener("fullscreenchange", () => {
        if (!previewModal) return;

        if (document.fullscreenElement !== previewModal) {
            previewModal.classList.remove("cursorHidden");
            clearCursorTimer();
        } else if (ss.playing) {
            scheduleCursorHide();
        }
    });

    document.addEventListener("keydown", (e) => {
        const previewOpen = isPreviewOpen();
        const metaOpen = !!(metaModal && metaModal.classList.contains("show"));
        const setupOpen = !!(slideshowModal && slideshowModal.classList.contains("show"));

        if (setupOpen) {
            if (e.key === "Escape") {
                e.preventDefault();
                closeSetupModal();
            }
            return;
        }

        if (!previewOpen) return;
        if (metaOpen) return;

        const t = e.target;
        if (t && t.closest && t.closest("input, textarea, select")) return;

        if (e.code === "Space") {
            e.preventDefault();
            if (ss.playing) {
                pause("Slideshow paused.");
            } else if (ss.items.length >= 2) {
                ss.playing = true;
                syncSlideshowFullscreenClass();
                PG.setBadge?.("warn", "slideshow");
                PG.setStatus?.("Slideshow resumed.");
                applyUi();
                scheduleNext();
            } else {
                openSetupModal();
            }
        }
    });

    window.addEventListener("photogallery:preview-open", () => {
        applyUi();
        updateSlideMetaOverlay();
        if (ss.playing) {
            scheduleNext();
        }
    });

    window.addEventListener("photogallery:preview-close", () => {
        stop("");
        updateSlideMetaOverlay();
    });

    window.addEventListener("photogallery:meta-open", () => {
        if (ss.playing) {
            pause("Slideshow paused while metadata is open.");
        }
    });

    window.addEventListener("photogallery:view-updated", () => {
        applyUi();
        if (slideshowModal && slideshowModal.classList.contains("show")) {
            updateSetupSummary();
        }
    });

    loadPrefs();
    applyUi();
})();