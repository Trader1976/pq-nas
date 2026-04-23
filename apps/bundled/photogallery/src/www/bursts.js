(() => {
    "use strict";

    const PG = window.PQNAS_PHOTOGALLERY = window.PQNAS_PHOTOGALLERY || {};

    const state = {
        enabled: true,
        thresholdSec: 2,
        maxSpanSec: 10,
        expandedKeys: new Set()
    };

    function currentRelPathFor(item) {
        return PG.currentRelPathFor ? PG.currentRelPathFor(item) : "";
    }

    function folderPathOf(item) {
        const rel = currentRelPathFor(item);
        const i = rel.lastIndexOf("/");
        return i >= 0 ? rel.slice(0, i) : "";
    }

    function itemCaptureTime(item) {
        const n = Number(item && item.capture_time_unix || 0);
        return Number.isFinite(n) ? n : 0;
    }

    function isImageFile(item) {
        return !!item && item.type === "file";
    }

    function burstKey(folderPath, firstRelPath) {
        return `${folderPath}::${firstRelPath}`;
    }

    function pickCoverIndex(items) {
        if (!Array.isArray(items) || !items.length) return 0;

        let bestIdx = 0;
        let bestScore = -Infinity;

        for (let i = 0; i < items.length; i++) {
            const it = items[i] || {};
            const rating = Number(it.rating || it.imageRating || 0) || 0;
            const pixels = (Number(it.width || 0) || 0) * (Number(it.height || 0) || 0);
            const size = Number(it.size_bytes || 0) || 0;

            const score =
                rating * 1e15 +
                pixels * 1e6 +
                size;

            if (score > bestScore) {
                bestScore = score;
                bestIdx = i;
            }
        }

        if (bestScore <= 0) {
            return Math.floor(items.length / 2);
        }

        return bestIdx;
    }

    function clusterFolderImages(items) {
        const thresholdSec = Number(state.thresholdSec || 2);
        const maxSpanSec = Number(state.maxSpanSec || 10);

        const sorted = items.slice().sort((a, b) => {
            const ta = itemCaptureTime(a);
            const tb = itemCaptureTime(b);
            if (ta !== tb) return ta - tb;
            return String(a.name || "").localeCompare(String(b.name || ""));
        });

        const groups = [];
        let cur = [];

        const flush = () => {
            if (cur.length >= 2) {
                groups.push(cur.slice());
            } else if (cur.length === 1) {
                groups.push(cur.slice());
            }
            cur = [];
        };

        for (const item of sorted) {
            const t = itemCaptureTime(item);

            if (!t) {
                flush();
                groups.push([item]);
                continue;
            }

            if (!cur.length) {
                cur.push(item);
                continue;
            }

            const prev = cur[cur.length - 1];
            const first = cur[0];
            const dtPrev = t - itemCaptureTime(prev);
            const dtFirst = t - itemCaptureTime(first);

            if (dtPrev <= thresholdSec && dtFirst <= maxSpanSec) {
                cur.push(item);
            } else {
                flush();
                cur.push(item);
            }
        }

        flush();
        return groups;
    }

    function buildDisplayItems(items) {
        const src = Array.isArray(items) ? items.slice() : [];

        if (!state.enabled) {
            return src.map((item, idx) => ({
                kind: "item",
                item,
                sortIndex: idx
            }));
        }

        const originalIndexByRel = new Map();
        src.forEach((item, idx) => {
            originalIndexByRel.set(currentRelPathFor(item), idx);
        });

        const out = [];
        const filesByFolder = new Map();

        for (let i = 0; i < src.length; i++) {
            const item = src[i];
            if (!item) continue;

            if (item.type !== "file") {
                out.push({
                    kind: "item",
                    item,
                    sortIndex: i
                });
                continue;
            }

            const folder = folderPathOf(item);
            if (!filesByFolder.has(folder)) filesByFolder.set(folder, []);
            filesByFolder.get(folder).push(item);
        }

        const folderKeys = Array.from(filesByFolder.keys()).sort((a, b) => a.localeCompare(b));

        for (const folder of folderKeys) {
            const groups = clusterFolderImages(filesByFolder.get(folder) || []);

            for (const g of groups) {
                const sortIndex = Math.min(
                    ...g.map((it) => {
                        const rel = currentRelPathFor(it);
                        const idx = originalIndexByRel.get(rel);
                        return Number.isFinite(idx) ? idx : 999999999;
                    })
                );

                if (g.length < 2) {
                    out.push({
                        kind: "item",
                        item: g[0],
                        sortIndex
                    });
                    continue;
                }

                const coverIdx = pickCoverIndex(g);
                const cover = g[coverIdx];
                const key = burstKey(folder, currentRelPathFor(g[0]));
                const expanded = state.expandedKeys.has(key);

                out.push({
                    kind: "burst",
                    sortIndex,
                    burst: {
                        key,
                        folder,
                        items: g.slice(),
                        cover,
                        coverIdx,
                        expanded
                    }
                });
            }
        }

        out.sort((a, b) => a.sortIndex - b.sortIndex);
        return out;
    }

    function isExpanded(key) {
        return state.expandedKeys.has(String(key || ""));
    }

    function toggleExpanded(key) {
        key = String(key || "");
        if (!key) return false;

        if (state.expandedKeys.has(key)) {
            state.expandedKeys.delete(key);
            return false;
        }

        state.expandedKeys.add(key);
        return true;
    }

    function setEnabled(v) {
        state.enabled = !!v;
    }

    PG.bursts = {
        buildDisplayItems,
        isExpanded,
        toggleExpanded,
        setEnabled,
        getThresholdSec: () => state.thresholdSec,
        setThresholdSec: (n) => {
            const x = Number(n || 2);
            if (Number.isFinite(x) && x >= 1 && x <= 10) state.thresholdSec = x;
        }
    };
})();