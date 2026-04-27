(() => {
    "use strict";

    const el = (id) => document.getElementById(id);

    let listEl = null;
    let pending = false;

    function esc(s) {
        return String(s ?? "").replace(/[&<>"']/g, (c) => ({
            "&": "&amp;",
            "<": "&lt;",
            ">": "&gt;",
            '"': "&quot;",
            "'": "&#39;"
        }[c]));
    }

    function stripExt(name) {
        return String(name || "").replace(/\.[^.\/\\]+$/, "");
    }

    function cleanTitle(s) {
        return String(s || "")
            .replace(/_/g, " ")
            .replace(/\s+/g, " ")
            .replace(/^\s*[-–—]+\s*/, "")
            .replace(/\s*[-–—]+\s*$/, "")
            .trim();
    }

    function pathParts(path) {
        return String(path || "")
            .split("/")
            .map((x) => x.trim())
            .filter(Boolean);
    }

    function parseDiscFromParts(parts) {
        for (const p of parts) {
            const m = String(p).match(/^(?:cd|disc|disk)\s*0?(\d+)$/i);
            if (m) return `Disc ${Number(m[1])}`;
        }
        return "";
    }

    function parseYearFromText(s) {
        const m = String(s || "").match(/\b(19[5-9]\d|20[0-4]\d)\b/);
        return m ? m[1] : "";
    }

    function parseTrackAndTitle(fileBase) {
        let s = cleanTitle(stripExt(fileBase));
        let track = "";

        const m = s.match(/^\s*(?:cd\d+\s*[-_. ]*)?0?(\d{1,3})(?:\s*[.\-_)–—]\s+|\s+-\s+|\s+)/i);
        if (m) {
            track = m[1].padStart(2, "0");
            s = cleanTitle(s.slice(m[0].length));
        }

        return {
            track,
            title: cleanTitle(s)
        };
    }

    function parseArtistAlbumFromFolder(folder) {
        const raw = cleanTitle(folder);
        if (!raw) return { artist: "", album: "" };

        let s = raw;

        const year = parseYearFromText(s);
        s = cleanTitle(
            s
                .replace(/^\(?\b(19[5-9]\d|20[0-4]\d)\b\)?\s*[-–—]?\s*/i, "")
                .replace(/\s*\(\b(19[5-9]\d|20[0-4]\d)\b\)\s*/i, " ")
        );

        const parts = s.split(/\s+[-–—]\s+/).map(cleanTitle).filter(Boolean);

        if (parts.length >= 2) {
            return {
                artist: parts[0],
                album: parts.slice(1).join(" - "),
                year
            };
        }

        return {
            artist: "",
            album: s,
            year
        };
    }

    function parseMetadata(path, name) {
        const parts = pathParts(path);
        const fileName = name || parts[parts.length - 1] || "";
        const fileBase = stripExt(fileName);

        const parent = parts.length >= 2 ? parts[parts.length - 2] : "";
        const grandParent = parts.length >= 3 ? parts[parts.length - 3] : "";

        const disc = parseDiscFromParts(parts);
        const albumFolder = disc && grandParent ? grandParent : parent;

        const parsedFile = parseTrackAndTitle(fileBase);
        const parsedFolder = parseArtistAlbumFromFolder(albumFolder);

        let artist = parsedFolder.artist || "";
        let album = parsedFolder.album || "";
        let year = parsedFolder.year || parseYearFromText(path);

        // Filename fallback: "Artist - Title"
        if (!artist) {
            const bits = parsedFile.title.split(/\s+[-–—]\s+/).map(cleanTitle).filter(Boolean);
            if (bits.length >= 2) {
                artist = bits[0];
                parsedFile.title = bits.slice(1).join(" - ");
            }
        }

        return {
            track: parsedFile.track,
            title: parsedFile.title,
            artist,
            album,
            year,
            disc
        };
    }

    function metadataChips(meta) {
        const chips = [];

        if (meta.track) chips.push(`Track ${meta.track}`);
        if (meta.artist) chips.push(meta.artist);
        if (meta.album) chips.push(meta.album);
        if (meta.year) chips.push(meta.year);
        if (meta.disc) chips.push(meta.disc);

        return chips;
    }

    function enhanceRows() {
        pending = false;
        if (!listEl) return;

        const rows = Array.from(listEl.querySelectorAll(".item"));

        for (const row of rows) {
            if (row.dataset.nwMetadataDone === "1") continue;

            const kind = row.dataset.kind || "";
            if (kind !== "audio") {
                row.dataset.nwMetadataDone = "1";
                continue;
            }

            const path = row.dataset.path || "";
            const name = row.dataset.name || "";
            const meta = parseMetadata(path, name);
            const chips = metadataChips(meta);

            if (!chips.length) {
                row.dataset.nwMetadataDone = "1";
                continue;
            }

            const mid = row.querySelector(".itemName")?.parentElement;
            if (!mid) {
                row.dataset.nwMetadataDone = "1";
                continue;
            }

            const div = document.createElement("div");
            div.className = "nwMetadataLine";
            div.innerHTML = chips.map((c) => `<span>${esc(c)}</span>`).join("");

            mid.appendChild(div);
            row.dataset.nwMetadataDone = "1";
        }
    }

    function scheduleEnhance() {
        if (pending) return;
        pending = true;
        window.requestAnimationFrame(enhanceRows);
    }

    function init() {
        listEl = el("list");
        if (!listEl) return;

        const observer = new MutationObserver(scheduleEnhance);
        observer.observe(listEl, { childList: true });

        scheduleEnhance();

        window.PQNAS_NEONWAVE_METADATA = {
            parse: parseMetadata,
            refresh: enhanceRows
        };
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", init, { once: true });
    } else {
        init();
    }
})();