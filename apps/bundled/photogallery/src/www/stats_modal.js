(() => {
    "use strict";

    const PG = window.PQNAS_PHOTOGALLERY;
    if (!PG || !PG.statsApi || !PG.statsCharts) return;

    const el = (id) => document.getElementById(id);

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
            statsSub.textContent = path ? `Under /${path}` : "Whole library";
        }

        if (statsStatus) {
            statsStatus.textContent = "Loading statistics…";
        }

        let stats = null;
        const cached = cache.get(key);

        if (!force && cached && (now - cached.ts) < CACHE_MS) {
            stats = cached.data;
        } else {
            PG.setBadge?.("warn", "stats…");
            PG.setStatus?.("Loading photo statistics…");
            stats = await PG.statsApi.fetchStats({ path });
            cache.set(key, { ts: now, data: stats });
        }

        PG.statsCharts.renderSummary(statsSummary, stats);
        PG.statsCharts.renderTopList(statsTopCameras, stats.topCameras, "No camera data.");
        PG.statsCharts.renderTopList(statsTopLenses, stats.topLenses, "No lens data.");
        PG.statsCharts.renderChart(statsIsoChart, stats.iso, "No ISO data.");
        PG.statsCharts.renderChart(statsApertureChart, stats.aperture, "No aperture data.");
        PG.statsCharts.renderChart(statsShutterChart, stats.shutter, "No shutter speed data.");
        PG.statsCharts.renderChart(statsFocalChart, stats.focal, "No focal length data.");
        PG.statsCharts.renderChart(statsByMonthChart, stats.byMonth, "No date histogram data.");

        if (statsStatus) {
            statsStatus.textContent =
                `${PG.statsCharts.fmtInt(stats.totalPhotos)} photos • ${PG.statsCharts.fmtBytes(stats.totalBytes)} total`;
        }

        PG.setBadge?.("ok", "ready");
        PG.setStatus?.("Photo statistics ready.");
    }

    async function openAndLoad(force = false) {
        openModal();
        clearOutputs();

        try {
            await loadStats(force);
        } catch (e) {
            clearOutputs();
            if (statsStatus) {
                statsStatus.textContent = `Failed to load statistics: ${String(e && e.message ? e.message : e)}`;
            }
            PG.setBadge?.("err", "error");
            PG.setStatus?.("Photo statistics failed.");
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