(() => {
    "use strict";

    const PG = window.PQNAS_PHOTOGALLERY;
    if (!PG || !PG.statsApi || !PG.statsCharts) return;

    const el = (id) => document.getElementById(id);

    function statsT(key, params, fallback) {
        try {
            const api = window.PQNAS_I18N;
            if (api && typeof api.t === "function") {
                return api.t(key, params || null, fallback);
            }
        } catch (_) {}

        let out = String(fallback || key || "");
        const p = params || {};
        for (const name of Object.keys(p)) {
            out = out.split(`{${name}}`).join(String(p[name]));
        }
        return out;
    }

    const statsBtn = el("statsBtn");
    const statsModal = el("statsModal");
    const statsClose = el("statsClose");
    const statsSub = el("statsSub");
    const statsStatus = el("statsStatus");

    const statsSummary = el("statsSummary");
    const statsTopCameras = el("statsTopCameras");
    const statsTopLenses = el("statsTopLenses");
    const statsIsoChart = el("statsIsoChart");
    const statsApertureChart = el("statsApertureChart");
    const statsShutterChart = el("statsShutterChart");
    const statsFocalChart = el("statsFocalChart");
    const statsByMonthChart = el("statsByMonthChart");

    const cache = new Map();
    const CACHE_MS = 15000;

    function currentPath() {
        return (typeof PG.getCurrentPath === "function")
            ? String(PG.getCurrentPath() || "")
            : "";
    }

    function clearOutputs() {
        for (const node of [
            statsSummary,
            statsTopCameras,
            statsTopLenses,
            statsIsoChart,
            statsApertureChart,
            statsShutterChart,
            statsFocalChart,
            statsByMonthChart
        ]) {
            if (node) node.replaceChildren();
        }
    }

    function openModal() {
        if (!statsModal) return;
        statsModal.classList.add("show");
        statsModal.setAttribute("aria-hidden", "false");
    }

    function closeModal() {
        if (!statsModal) return;
        statsModal.classList.remove("show");
        statsModal.setAttribute("aria-hidden", "true");
    }

    async function loadStats(force = false) {
        const path = currentPath();
        const key = path || "/";
        const now = Date.now();

        if (statsSub) {
            statsSub.textContent = path
                ? statsT("photogallery.stats.under_path", { path }, "Under /{path}")
                : statsT("photogallery.stats.whole_library", null, "Whole library");
        }

        if (statsStatus) {
            statsStatus.textContent = statsT("photogallery.stats.loading_statistics", null, "Loading statistics…");
        }

        let stats = null;
        const cached = cache.get(key);

        if (!force && cached && (now - cached.ts) < CACHE_MS) {
            stats = cached.data;
        } else {
            PG.setBadge?.("warn", statsT("photogallery.badge.stats", null, "stats…"));
            PG.setStatus?.(statsT("photogallery.stats.loading_photo_statistics", null, "Loading photo statistics…"));
            stats = await PG.statsApi.fetchStats({ path });
            cache.set(key, { ts: now, data: stats });
        }

        PG.statsCharts.renderSummary(statsSummary, stats);
        PG.statsCharts.renderTopList(statsTopCameras, stats.topCameras, statsT("photogallery.stats.no_camera_data", null, "No camera data."));
        PG.statsCharts.renderTopList(statsTopLenses, stats.topLenses, statsT("photogallery.stats.no_lens_data", null, "No lens data."));
        PG.statsCharts.renderChart(statsIsoChart, stats.iso, statsT("photogallery.stats.no_iso_data", null, "No ISO data."));
        PG.statsCharts.renderChart(statsApertureChart, stats.aperture, statsT("photogallery.stats.no_aperture_data", null, "No aperture data."));
        PG.statsCharts.renderChart(statsShutterChart, stats.shutter, statsT("photogallery.stats.no_shutter_data", null, "No shutter speed data."));
        PG.statsCharts.renderChart(statsFocalChart, stats.focal, statsT("photogallery.stats.no_focal_data", null, "No focal length data."));
        PG.statsCharts.renderChart(statsByMonthChart, stats.byMonth, statsT("photogallery.stats.no_date_histogram_data", null, "No date histogram data."));

        if (statsStatus) {
            statsStatus.textContent =
                statsT("photogallery.stats.status_summary", {
                    photos: PG.statsCharts.fmtInt(stats.totalPhotos),
                    bytes: PG.statsCharts.fmtBytes(stats.totalBytes)
                }, "{photos} photos • {bytes} total");
        }

        PG.setBadge?.("ok", statsT("common.ready_badge", null, "ready"));
        PG.setStatus?.(statsT("photogallery.stats.ready_status", null, "Photo statistics ready."));
    }

    async function openAndLoad(force = false) {
        openModal();
        clearOutputs();

        try {
            await loadStats(force);
        } catch (e) {
            clearOutputs();
            if (statsStatus) {
                statsStatus.textContent = statsT("photogallery.stats.failed_to_load_with_error", {
                    error: String(e && e.message ? e.message : e)
                }, "Failed to load statistics: {error}");
            }
            PG.setBadge?.("err", statsT("common.error_badge", null, "error"));
            PG.setStatus?.(statsT("photogallery.stats.failed_status", null, "Photo statistics failed."));
        }
    }

    statsBtn?.addEventListener("click", () => {
        openAndLoad(false);
    });

    statsClose?.addEventListener("click", closeModal);

    statsModal?.addEventListener("click", (e) => {
        if (e.target === statsModal) {
            closeModal();
        }
    });

    document.addEventListener("keydown", (e) => {
        const open = !!(statsModal && statsModal.classList.contains("show"));
        if (!open) return;

        if (e.key === "Escape") {
            e.preventDefault();
            closeModal();
        }
    });

    window.addEventListener("photogallery:view-updated", () => {
        cache.clear();
    });

    PG.statsModal = {
        open: openAndLoad,
        close: closeModal,
        refresh: () => openAndLoad(true)
    };
})();