(() => {
    "use strict";

    const PG = window.PQNAS_PHOTOGALLERY = window.PQNAS_PHOTOGALLERY || {};

    function clear(el) {
        if (el) el.replaceChildren();
    }

    function fmtInt(n) {
        const x = Number(n || 0);
        return Number.isFinite(x) ? x.toLocaleString() : "0";
    }

    function fmtBytes(bytes) {
        let n = Number(bytes || 0);
        if (!Number.isFinite(n) || n < 0) return "0 B";

        const units = ["B", "KiB", "MiB", "GiB", "TiB"];
        let i = 0;
        while (n >= 1024 && i < units.length - 1) {
            n /= 1024;
            i++;
        }

        return i === 0 ? `${Math.round(n)} ${units[i]}` : `${n.toFixed(i === 1 ? 1 : 2)} ${units[i]}`;
    }

    function addEmpty(el, text) {
        if (!el) return;
        const d = document.createElement("div");
        d.className = "pgStatsEmpty";
        d.textContent = text;
        el.appendChild(d);
    }

    function makeCard(k, v, sub = "") {
        const card = document.createElement("div");
        card.className = "pgStatsCard";

        const kEl = document.createElement("div");
        kEl.className = "pgStatsCardK";
        kEl.textContent = k;

        const vEl = document.createElement("div");
        vEl.className = "pgStatsCardV";
        vEl.textContent = v;

        card.appendChild(kEl);
        card.appendChild(vEl);

        if (sub) {
            const subEl = document.createElement("div");
            subEl.className = "pgStatsCardSub";
            subEl.textContent = sub;
            card.appendChild(subEl);
        }

        return card;
    }

    function renderSummary(el, stats) {
        clear(el);
        if (!el) return;

        const rangeText =
            stats.firstTakenAt || stats.lastTakenAt
                ? `${stats.firstTakenAt || "?"} → ${stats.lastTakenAt || "?"}`
                : "No capture date data";

        el.appendChild(makeCard("Photos", fmtInt(stats.totalPhotos)));
        el.appendChild(makeCard("Total size", fmtBytes(stats.totalBytes), `${stats.totalMegabytes.toFixed(1)} MB`));
        el.appendChild(makeCard("Photos with EXIF", fmtInt(stats.photosWithExif)));
        el.appendChild(makeCard("Unique cameras", fmtInt(stats.uniqueCameras)));
        el.appendChild(makeCard("Unique lenses", fmtInt(stats.uniqueLenses)));
        el.appendChild(makeCard("Date range", stats.firstTakenAt || stats.lastTakenAt ? "Available" : "Unknown", rangeText));
    }

    function renderBars(el, items, opts = {}) {
        clear(el);
        if (!el) return;

        const list = Array.isArray(items) ? items.slice(0, opts.maxItems || 12) : [];
        if (!list.length) {
            addEmpty(el, opts.emptyText || "No data.");
            return;
        }

        const max = Math.max(...list.map((x) => Number(x.count || 0)), 1);

        for (const item of list) {
            const row = document.createElement("div");
            row.className = "pgStatsRow";

            const head = document.createElement("div");
            head.className = "pgStatsRowHead";

            const label = document.createElement("div");
            label.className = "pgStatsRowLabel";
            label.textContent = item.label || "—";
            label.title = item.label || "";

            const value = document.createElement("div");
            value.className = "pgStatsRowValue";
            value.textContent = fmtInt(item.count);

            head.appendChild(label);
            head.appendChild(value);

            const bar = document.createElement("div");
            bar.className = "pgStatsBar";

            const fill = document.createElement("div");
            fill.className = "pgStatsBarFill";
            fill.style.width = `${Math.max(2, (Number(item.count || 0) / max) * 100)}%`;

            bar.appendChild(fill);
            row.appendChild(head);
            row.appendChild(bar);
            el.appendChild(row);
        }
    }

    PG.statsCharts = {
        fmtBytes,
        fmtInt,
        renderSummary,
        renderTopList(el, items, emptyText = "No data.") {
            renderBars(el, items, { maxItems: 8, emptyText });
        },
        renderChart(el, items, emptyText = "No data.") {
            renderBars(el, items, { maxItems: 16, emptyText });
        }
    };
})();