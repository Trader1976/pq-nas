(() => {
    "use strict";

    const PG = window.PQNAS_PHOTOGALLERY;
    if (!PG) return;

    const el = (id) => document.getElementById(id);

    const previewModal = el("previewModal");
    const metaModal = el("metaModal");

    const slideToggleBtn = el("previewSlideToggleBtn");
    const slideInterval = el("previewSlideInterval");
    const slideShuffle = el("previewSlideShuffle");
    const slideLoop = el("previewSlideLoop");

    const INTERVAL_KEY = "pqnas_photogallery_slideshow_interval_v1";
    const SHUFFLE_KEY = "pqnas_photogallery_slideshow_shuffle_v1";
    const LOOP_KEY = "pqnas_photogallery_slideshow_loop_v1";

    const ss = {
        playing: false,
        timer: null,
        intervalMs: 5000,
        shuffle: false,
        loop: true
    };

    function loadPrefs() {
        try {
            const iv = Number(localStorage.getItem(INTERVAL_KEY) || "5000");
            if (iv === 2000 || iv === 3000 || iv === 5000 || iv === 10000) {
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
    }

    function savePrefs() {
        try { localStorage.setItem(INTERVAL_KEY, String(ss.intervalMs)); } catch (_) {}
        try { localStorage.setItem(SHUFFLE_KEY, ss.shuffle ? "1" : "0"); } catch (_) {}
        try { localStorage.setItem(LOOP_KEY, ss.loop ? "1" : "0"); } catch (_) {}
    }

    function clearTimer() {
        if (ss.timer) {
            clearTimeout(ss.timer);
            ss.timer = null;
        }
    }

    function currentItems() {
        return PG.getFilteredImageItems ? PG.getFilteredImageItems() : [];
    }

    function currentIndex(items) {
        const cur = PG.getPreviewPath ? PG.getPreviewPath() : "";
        if (!cur) return -1;
        return items.findIndex((it) => PG.currentRelPathFor(it) === cur);
    }

    function isPreviewOpen() {
        return !!(PG.isPreviewOpen && PG.isPreviewOpen());
    }

    function applyUi() {
        const items = currentItems();
        const canRun = isPreviewOpen() && items.length > 1;

        if (slideToggleBtn) {
            slideToggleBtn.disabled = !canRun;
            slideToggleBtn.textContent = ss.playing ? "Pause" : "Slideshow";
            slideToggleBtn.title = ss.playing ? "Pause slideshow" : "Start slideshow";
        }

        if (slideInterval) slideInterval.value = String(ss.intervalMs);
        if (slideShuffle) slideShuffle.checked = !!ss.shuffle;
        if (slideLoop) slideLoop.checked = !!ss.loop;
    }

    function scheduleNext() {
        clearTimer();
        if (!ss.playing) return;

        ss.timer = setTimeout(() => {
            advance(+1, false);
        }, ss.intervalMs);
    }

    function stop(reason = "") {
        clearTimer();
        ss.playing = false;
        applyUi();
        if (reason) PG.setStatus?.(reason);
        PG.setBadge?.("ok", "ready");
    }

    function pause(reason = "") {
        if (!ss.playing) {
            applyUi();
            return;
        }
        clearTimer();
        ss.playing = false;
        applyUi();
        if (reason) PG.setStatus?.(reason);
        PG.setBadge?.("ok", "ready");
    }

    function start() {
        const items = currentItems();
        if (!isPreviewOpen()) {
            PG.setStatus?.("Open an image first.");
            applyUi();
            return;
        }
        if (items.length <= 1) {
            PG.setStatus?.("Need at least 2 filtered images for slideshow.");
            applyUi();
            return;
        }

        ss.playing = true;
        applyUi();

        PG.setBadge?.("warn", "slideshow");
        PG.setStatus?.(
            `Slideshow running • ${Math.round(ss.intervalMs / 1000)}s` +
            (ss.shuffle ? " • shuffle" : "") +
            (ss.loop ? " • loop" : "")
        );

        scheduleNext();
    }

    function pickNextIndex(items, idx, dir) {
        if (!items.length) return -1;
        if (items.length === 1) return 0;

        if (ss.shuffle) {
            let next = idx;
            let tries = 0;
            while (next === idx && tries < 16) {
                next = Math.floor(Math.random() * items.length);
                tries++;
            }
            if (next === idx) {
                next = (idx + 1) % items.length;
            }
            return next;
        }

        if (idx < 0) return 0;

        const next = idx + dir;
        if (next >= items.length) return ss.loop ? 0 : -1;
        if (next < 0) return ss.loop ? (items.length - 1) : -1;
        return next;
    }

    function advance(dir, manual) {
        const items = currentItems();
        if (!items.length) {
            stop("No images in current filtered view.");
            return;
        }

        let idx = currentIndex(items);
        if (idx < 0) idx = 0;

        const nextIdx = pickNextIndex(items, idx, dir);
        if (nextIdx < 0) {
            stop("Slideshow finished.");
            return;
        }

        PG.openPreviewFor(items[nextIdx]);

        if (ss.playing && !manual) {
            scheduleNext();
        } else if (ss.playing && manual) {
            scheduleNext();
        }
    }

    slideToggleBtn?.addEventListener("click", () => {
        if (ss.playing) pause("Slideshow paused.");
        else start();
    });

    slideInterval?.addEventListener("change", () => {
        const v = Number(slideInterval.value || "5000");
        if (v === 2000 || v === 3000 || v === 5000 || v === 10000) {
            ss.intervalMs = v;
            savePrefs();
            if (ss.playing) {
                PG.setStatus?.(`Slideshow interval set to ${Math.round(v / 1000)}s.`);
                scheduleNext();
            }
            applyUi();
        }
    });

    slideShuffle?.addEventListener("change", () => {
        ss.shuffle = !!slideShuffle.checked;
        savePrefs();
        applyUi();
        if (ss.playing) scheduleNext();
    });

    slideLoop?.addEventListener("change", () => {
        ss.loop = !!slideLoop.checked;
        savePrefs();
        applyUi();
    });

    document.addEventListener("keydown", (e) => {
        if (!isPreviewOpen()) return;
        if (metaModal && metaModal.classList.contains("show")) return;

        const t = e.target;
        if (t && t.closest && t.closest("input, textarea, select")) return;

        if (e.code === "Space") {
            e.preventDefault();
            if (ss.playing) pause("Slideshow paused.");
            else start();
        }
    });

    window.addEventListener("photogallery:preview-open", () => {
        applyUi();
        if (ss.playing) {
            scheduleNext();
        }
    });

    window.addEventListener("photogallery:preview-close", () => {
        stop("");
    });

    window.addEventListener("photogallery:meta-open", () => {
        if (ss.playing) {
            pause("Slideshow paused while metadata is open.");
        }
    });

    window.addEventListener("photogallery:view-updated", () => {
        applyUi();
    });

    loadPrefs();
    applyUi();
})();