(() => {
    "use strict";

    const PG = window.PQNAS_PHOTOGALLERY = window.PQNAS_PHOTOGALLERY || {};

    const JPEG_EXTS = new Set(["jpg", "jpeg"]);
    const RAW_EXTS = new Set(["cr2", "cr3", "nef", "arw", "raf", "dng", "rw2", "orf"]);
    const RAW_PAIR_MAX_DT_SEC = 1;

    const state = PG._burstsState = PG._burstsState || {
        enabled: true,
        thresholdSec: 2,
        maxSpanSec: 12,
        expandedKeys: new Set()
    };

    function num(v, d = 0) {
        const n = Number(v);
        return Number.isFinite(n) ? n : d;
    }

    function str(v, d = "") {
        return v == null ? d : String(v);
    }

    function currentRelPathFor(item) {
        if (!item) return "";
        if (typeof PG.currentRelPathFor === "function") {
            return String(PG.currentRelPathFor(item) || "");
        }
        if (item.rel_path) return String(item.rel_path);
        if (item.path) return String(item.path);
        return String(item.name || "");
    }

    function parentPath(p) {
        p = String(p || "");
        if (!p) return "";
        const i = p.lastIndexOf("/");
        return i < 0 ? "" : p.slice(0, i);
    }

    function folderPathOf(item) {
        return parentPath(currentRelPathFor(item));
    }

    function extLower(name) {
        const s = String(name || "");
        const i = s.lastIndexOf(".");
        return i >= 0 ? s.slice(i + 1).toLowerCase() : "";
    }

    function stemOnly(name) {
        const s = String(name || "");
        const i = s.lastIndexOf(".");
        return i >= 0 ? s.slice(0, i) : s;
    }

    function isJpegItem(item) {
        return JPEG_EXTS.has(extLower(item && item.name));
    }

    function isRawItem(item) {
        return RAW_EXTS.has(extLower(item && item.name));
    }

    function itemCaptureTime(item) {
        return num(item && item.capture_time_unix, 0);
    }

    function bestCaptureTime(a, b) {
        const ta = itemCaptureTime(a);
        const tb = itemCaptureTime(b);
        if (ta && tb) return Math.min(ta, tb);
        return ta || tb || 0;
    }

    function burstKey(folder, anchorKey) {
        return `burst:${folder || ""}:${anchorKey || ""}`;
    }

    function makeSingleCapture(item, sortIndex, folder) {
        return {
            kind: "capture",
            key: `cap:${currentRelPathFor(item)}`,
            folder,
            sortIndex,
            capture_time_unix: itemCaptureTime(item),
            preview_item: item,
            jpeg_item: isJpegItem(item) ? item : null,
            raw_item: isRawItem(item) ? item : null,
            items: [item],
            pair_kind: "single",
            has_raw: isRawItem(item),
            has_jpeg: isJpegItem(item)
        };
    }

    function makeRawJpegCapture(jpegItem, rawItem, sortIndex, folder) {
        const preview = jpegItem || rawItem || null;
        return {
            kind: "capture",
            key: `cap:${folder}/${stemOnly(jpegItem?.name || rawItem?.name || "")}`,
            folder,
            sortIndex,
            capture_time_unix: bestCaptureTime(jpegItem, rawItem),
            preview_item: preview,
            jpeg_item: jpegItem || null,
            raw_item: rawItem || null,
            items: [jpegItem, rawItem].filter(Boolean),
            pair_kind: "raw+jpeg",
            has_raw: !!rawItem,
            has_jpeg: !!jpegItem
        };
    }

    function buildCaptureItems(items) {
        const src = Array.isArray(items) ? items.slice() : [];
        const originalIndexByRel = new Map();

        src.forEach((item, idx) => {
            originalIndexByRel.set(currentRelPathFor(item), idx);
        });

        const folders = new Map();

        for (const item of src) {
            if (!item || item.type !== "file") continue;

            const folder = folderPathOf(item);
            if (!folders.has(folder)) folders.set(folder, []);
            folders.get(folder).push(item);
        }

        const captures = [];

        for (const [folder, files] of folders) {
            const byStem = new Map();

            for (const item of files) {
                const stem = stemOnly(item.name || "");
                const key = `${folder}::${stem}`;
                if (!byStem.has(key)) byStem.set(key, []);
                byStem.get(key).push(item);
            }

            for (const group of byStem.values()) {
                const jpegs = group.filter(isJpegItem);
                const raws = group.filter(isRawItem);
                const others = group.filter((it) => !isJpegItem(it) && !isRawItem(it));

                const usedJpegs = new Set();
                const usedRaws = new Set();

                // Conservative same-stem RAW+JPG pairing.
                for (let i = 0; i < jpegs.length; i++) {
                    const jpg = jpegs[i];

                    let bestRaw = null;
                    let bestRawIdx = -1;
                    let bestDt = Infinity;

                    for (let r = 0; r < raws.length; r++) {
                        if (usedRaws.has(r)) continue;

                        const raw = raws[r];
                        const tj = itemCaptureTime(jpg);
                        const tr = itemCaptureTime(raw);

                        let ok = true;
                        let dt = 0;

                        if (tj && tr) {
                            dt = Math.abs(tj - tr);
                            ok = dt <= RAW_PAIR_MAX_DT_SEC;
                        }

                        if (!ok) continue;

                        if (dt < bestDt) {
                            bestDt = dt;
                            bestRaw = raw;
                            bestRawIdx = r;
                        }
                    }

                    if (bestRaw) {
                        usedJpegs.add(i);
                        usedRaws.add(bestRawIdx);

                        const sortIndex = Math.min(
                            originalIndexByRel.get(currentRelPathFor(jpg)) ?? 999999999,
                            originalIndexByRel.get(currentRelPathFor(bestRaw)) ?? 999999999
                        );

                        captures.push(makeRawJpegCapture(jpg, bestRaw, sortIndex, folder));
                    }
                }

                for (let i = 0; i < jpegs.length; i++) {
                    if (usedJpegs.has(i)) continue;
                    const item = jpegs[i];
                    const sortIndex = originalIndexByRel.get(currentRelPathFor(item)) ?? 999999999;
                    captures.push(makeSingleCapture(item, sortIndex, folder));
                }

                for (let i = 0; i < raws.length; i++) {
                    if (usedRaws.has(i)) continue;
                    const item = raws[i];
                    const sortIndex = originalIndexByRel.get(currentRelPathFor(item)) ?? 999999999;
                    captures.push(makeSingleCapture(item, sortIndex, folder));
                }

                for (const item of others) {
                    const sortIndex = originalIndexByRel.get(currentRelPathFor(item)) ?? 999999999;
                    captures.push(makeSingleCapture(item, sortIndex, folder));
                }
            }
        }

        captures.sort((a, b) => a.sortIndex - b.sortIndex);
        return captures;
    }

    function captureTimeOf(capture) {
        return num(capture && capture.capture_time_unix, 0);
    }

    function clusterFolderCaptures(captures) {
        const thresholdSec = num(state.thresholdSec, 2);
        const maxSpanSec = num(state.maxSpanSec, 12);

        const sorted = (Array.isArray(captures) ? captures.slice() : []).sort((a, b) => {
            const ta = captureTimeOf(a);
            const tb = captureTimeOf(b);
            if (ta !== tb) return ta - tb;
            return num(a && a.sortIndex, 999999999) - num(b && b.sortIndex, 999999999);
        });

        const groups = [];
        let cur = [];

        function flush() {
            if (cur.length) groups.push(cur.slice());
            cur = [];
        }

        for (const cap of sorted) {
            const t = captureTimeOf(cap);

            if (!t) {
                flush();
                groups.push([cap]);
                continue;
            }

            if (!cur.length) {
                cur.push(cap);
                continue;
            }

            const prev = cur[cur.length - 1];
            const first = cur[0];

            const dtPrev = t - captureTimeOf(prev);
            const dtFirst = t - captureTimeOf(first);

            if (dtPrev <= thresholdSec && dtFirst <= maxSpanSec) {
                cur.push(cap);
            } else {
                flush();
                cur.push(cap);
            }
        }

        flush();
        return groups;
    }

    function pickCoverCaptureIndex(captures) {
        if (!Array.isArray(captures) || !captures.length) return 0;

        let bestIdx = 0;
        let bestScore = -Infinity;

        for (let i = 0; i < captures.length; i++) {
            const preview = captures[i] && captures[i].preview_item ? captures[i].preview_item : {};
            const rating = num(preview.rating ?? preview.imageRating, 0);
            const size = num(preview.size_bytes, 0);

            const score = rating * 1e12 + size;
            if (score > bestScore) {
                bestScore = score;
                bestIdx = i;
            }
        }

        return bestIdx;
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

        const out = [];

        // Keep directories in their natural position.
        for (let i = 0; i < src.length; i++) {
            const item = src[i];
            if (item && item.type === "dir") {
                out.push({
                    kind: "item",
                    item,
                    sortIndex: i
                });
            }
        }

        const captures = buildCaptureItems(src);
        const capturesByFolder = new Map();

        for (const cap of captures) {
            if (!capturesByFolder.has(cap.folder)) capturesByFolder.set(cap.folder, []);
            capturesByFolder.get(cap.folder).push(cap);
        }

        for (const [folder, folderCaptures] of capturesByFolder) {
            const groups = clusterFolderCaptures(folderCaptures);

            for (const g of groups) {
                const sortIndex = Math.min(...g.map((c) => num(c.sortIndex, 999999999)));

                if (g.length < 2) {
                    const cap = g[0];
                    const preview = cap && cap.preview_item ? cap.preview_item : null;
                    if (preview) {
                        preview._pg_capture = cap;
                        out.push({
                            kind: "item",
                            item: preview,
                            sortIndex
                        });
                    }
                    continue;
                }

                const coverIdx = pickCoverCaptureIndex(g);
                const coverCapture = g[coverIdx];
                const key = burstKey(folder, coverCapture && coverCapture.key ? coverCapture.key : String(sortIndex));
                const expanded = state.expandedKeys.has(key);

                for (const cap of g) {
                    if (cap && cap.preview_item) {
                        cap.preview_item._pg_capture = cap;
                    }
                }

                out.push({
                    kind: "burst",
                    sortIndex,
                    burst: {
                        key,
                        folder,
                        captures: g.slice(),
                        items: g.map((c) => c.preview_item).filter(Boolean), // compatibility for existing app.js
                        cover: coverCapture.preview_item,
                        cover_capture: coverCapture,
                        coverIdx,
                        expanded
                    }
                });
            }
        }

        out.sort((a, b) => num(a.sortIndex, 999999999) - num(b.sortIndex, 999999999));
        return out;
    }

    function toggleExpanded(key) {
        key = str(key);
        if (!key) return false;

        if (state.expandedKeys.has(key)) {
            state.expandedKeys.delete(key);
            return false;
        }

        state.expandedKeys.add(key);
        return true;
    }

    function collapseAll() {
        state.expandedKeys.clear();
    }

    function setEnabled(v) {
        state.enabled = !!v;
    }

    function setThresholdSec(v) {
        state.thresholdSec = Math.max(1, num(v, 2));
    }

    function setMaxSpanSec(v) {
        state.maxSpanSec = Math.max(1, num(v, 12));
    }

    PG.bursts = {
        buildDisplayItems,
        buildCaptureItems,
        toggleExpanded,
        collapseAll,
        setEnabled,
        setThresholdSec,
        setMaxSpanSec,
        getState() {
            return {
                enabled: !!state.enabled,
                thresholdSec: state.thresholdSec,
                maxSpanSec: state.maxSpanSec,
                expandedKeys: Array.from(state.expandedKeys)
            };
        }
    };
})();