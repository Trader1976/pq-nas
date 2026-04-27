(() => {
    "use strict";

    const STORAGE_KEY = "pqnas_neonwave_history_v1";
    const MAX_TRACKS = 300;

    const el = (id) => document.getElementById(id);

    let mode = "recent";
    let listEl = null;
    let recentBtn = null;
    let mostBtn = null;
    let clearBtn = null;

    function esc(s) {
        return String(s ?? "").replace(/[&<>"']/g, (c) => ({
            "&": "&amp;",
            "<": "&lt;",
            ">": "&gt;",
            '"': "&quot;",
            "'": "&#39;"
        }[c]));
    }

    function normPath(p) {
        p = String(p || "").trim();
        if (!p) return "";
        if (!p.startsWith("/")) p = "/" + p;
        return p.replace(/\/+/g, "/");
    }

    function apiPath(p) {
        p = normPath(p);
        if (p === "/") return "";
        return p.replace(/^\/+/, "");
    }

    function coverUrl(path) {
        return `/api/v4/files/get?path=${encodeURIComponent(apiPath(path))}`;
    }

    function loadHistory() {
        try {
            const raw = localStorage.getItem(STORAGE_KEY);
            const j = raw ? JSON.parse(raw) : {};
            return j && typeof j === "object" && !Array.isArray(j) ? j : {};
        } catch {
            return {};
        }
    }

    function saveHistory(history) {
        try {
            localStorage.setItem(STORAGE_KEY, JSON.stringify(history));
        } catch {
            // Ignore private-mode/storage failures.
        }
    }

    function asTrack(input) {
        const path = normPath(input && input.path);
        if (!path || path === "/") return null;

        return {
            name: String(input.name || path.split("/").pop() || "Track"),
            path,
            cover: normPath(input.cover || ""),
            plays: Math.max(0, Number(input.plays || 0)),
            firstPlayed: Math.max(0, Number(input.firstPlayed || 0)),
            lastPlayed: Math.max(0, Number(input.lastPlayed || 0))
        };
    }

    function trimHistory(history) {
        const rows = Object.values(history)
            .map(asTrack)
            .filter(Boolean)
            .sort((a, b) => b.lastPlayed - a.lastPlayed)
            .slice(0, MAX_TRACKS);

        const out = {};
        for (const t of rows) out[t.path] = t;
        return out;
    }

    function recordTrack(track) {
        const clean = asTrack(track);
        if (!clean) return;

        const now = Date.now();
        let history = loadHistory();

        const old = asTrack(history[clean.path]) || {
            name: clean.name,
            path: clean.path,
            cover: clean.cover,
            plays: 0,
            firstPlayed: now,
            lastPlayed: 0
        };

        old.name = clean.name || old.name;
        old.cover = clean.cover || old.cover || "";
        old.plays = Math.max(0, Number(old.plays || 0)) + 1;
        old.lastPlayed = now;
        old.firstPlayed = old.firstPlayed || now;

        history[clean.path] = old;
        history = trimHistory(history);
        saveHistory(history);
        render();
    }

    function timeAgo(ts) {
        ts = Number(ts || 0);
        if (!ts) return "";

        const sec = Math.max(1, Math.round((Date.now() - ts) / 1000));
        if (sec < 60) return "just now";

        const min = Math.round(sec / 60);
        if (min < 60) return `${min} min ago`;

        const hr = Math.round(min / 60);
        if (hr < 48) return `${hr} h ago`;

        const days = Math.round(hr / 24);
        return `${days} d ago`;
    }

    function sortedTracks() {
        const rows = Object.values(loadHistory()).map(asTrack).filter(Boolean);

        if (mode === "most") {
            rows.sort((a, b) =>
                (b.plays - a.plays) ||
                (b.lastPlayed - a.lastPlayed) ||
                a.name.localeCompare(b.name)
            );
        } else {
            rows.sort((a, b) =>
                (b.lastPlayed - a.lastPlayed) ||
                a.name.localeCompare(b.name)
            );
        }

        return rows.slice(0, 12);
    }

    function setMode(next) {
        mode = next === "most" ? "most" : "recent";

        recentBtn?.classList.toggle("active", mode === "recent");
        mostBtn?.classList.toggle("active", mode === "most");

        render();
    }

    function playTrack(t) {
        const api = window.NEONWAVE_APP_API;
        if (api && typeof api.setQueue === "function") {
            api.setQueue([t], true);
            return;
        }

        alert("NeonWave player API is not ready yet.");
    }

    function queueTrack(t) {
        const api = window.NEONWAVE_APP_API;
        if (api && typeof api.addToQueueMany === "function") {
            api.addToQueueMany([t], false);
            return;
        }

        alert("NeonWave player API is not ready yet.");
    }

    function renderCover(track) {
        if (!track.cover) return `<div class="historyCover">♪</div>`;

        return `
            <div class="historyCover hasCover">
                <img src="${esc(coverUrl(track.cover))}" alt="" loading="lazy" decoding="async">
            </div>
        `;
    }

    function render() {
        if (!listEl) return;

        const rows = sortedTracks();

        if (!rows.length) {
            listEl.innerHTML = `<div class="empty">No listening history yet.</div>`;
            return;
        }

        listEl.innerHTML = "";

        for (const t of rows) {
            const row = document.createElement("div");
            row.className = "historyItem";
            row.innerHTML = `
                ${renderCover(t)}
                <div class="historyMid">
                    <div class="historyName">${esc(t.name)}</div>
                    <div class="historyMeta">${esc(t.path)}</div>
                    <div class="historyStats">${esc(`${t.plays} play${t.plays === 1 ? "" : "s"} · ${timeAgo(t.lastPlayed)}`)}</div>
                </div>
                <div class="historyActions">
                    <button class="pillBtn small" type="button" data-act="play">Play</button>
                    <button class="pillBtn small" type="button" data-act="queue">Queue</button>
                </div>
            `;

            row.querySelector('[data-act="play"]')?.addEventListener("click", () => playTrack(t));
            row.querySelector('[data-act="queue"]')?.addEventListener("click", () => queueTrack(t));

            listEl.appendChild(row);
        }
    }

    function clearHistory() {
        if (!confirm("Clear NeonWave listening history in this browser?")) return;
        saveHistory({});
        render();
    }

    function init() {
        listEl = el("historyList");
        recentBtn = el("historyRecentBtn");
        mostBtn = el("historyMostBtn");
        clearBtn = el("historyClearBtn");

        if (!listEl) return;

        recentBtn?.addEventListener("click", () => setMode("recent"));
        mostBtn?.addEventListener("click", () => setMode("most"));
        clearBtn?.addEventListener("click", clearHistory);

        window.addEventListener("neonwave:trackchange", (ev) => {
            recordTrack(ev.detail || {});
        });

        render();
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", init, { once: true });
    } else {
        init();
    }
})();
