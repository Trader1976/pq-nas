(() => {
    "use strict";

    const el = (id) => document.getElementById(id);

    let audio = null;

    function api() {
        return window.PQNAS_NEONWAVE_APP || null;
    }

    function typingTarget(ev) {
        const tag = String(ev.target?.tagName || "").toLowerCase();
        return tag === "input" ||
            tag === "textarea" ||
            tag === "select" ||
            ev.target?.isContentEditable;
    }

    function queueState() {
        const a = api();
        if (!a || typeof a.getQueueState !== "function") {
            return { queue: [], currentIndex: -1 };
        }

        const st = a.getQueueState();
        return {
            queue: Array.isArray(st.queue) ? st.queue : [],
            currentIndex: Number.isInteger(st.currentIndex) ? st.currentIndex : -1
        };
    }

    function currentTrack() {
        const st = queueState();
        if (st.currentIndex < 0 || st.currentIndex >= st.queue.length) return null;
        return st.queue[st.currentIndex];
    }

    function playPause() {
        if (!audio) return;

        if (audio.paused) {
            audio.play().catch(() => {});
        } else {
            audio.pause();
        }
    }

    function nextTrack() {
        const a = api();
        const st = queueState();

        if (!a || typeof a.playQueueIndex !== "function") return;
        if (!st.queue.length) return;

        if (st.currentIndex + 1 < st.queue.length) {
            a.playQueueIndex(st.currentIndex + 1);
        } else {
            a.playQueueIndex(0);
        }
    }

    function previousTrack() {
        const a = api();
        const st = queueState();

        if (!a || typeof a.playQueueIndex !== "function") return;
        if (!st.queue.length) return;

        if (audio && audio.currentTime > 4) {
            audio.currentTime = 0;
            return;
        }

        if (st.currentIndex > 0) {
            a.playQueueIndex(st.currentIndex - 1);
        } else {
            a.playQueueIndex(st.queue.length - 1);
        }
    }

    function seekBy(seconds) {
        if (!audio || !Number.isFinite(audio.duration)) return;
        audio.currentTime = Math.max(0, Math.min(audio.duration, audio.currentTime + seconds));
    }

    function volumeBy(delta) {
        if (!audio) return;
        audio.volume = Math.max(0, Math.min(1, audio.volume + delta));

        const a = api();
        if (a && typeof a.setStatus === "function") {
            a.setStatus(`Volume: ${Math.round(audio.volume * 100)}%`);
        }
    }

    function coverUrl(path) {
        if (!path) return "";
        const p = String(path || "/").replace(/^\/+/, "");
        return `/api/v4/files/get?path=${encodeURIComponent(p)}`;
    }

    function updateMediaSession() {
        if (!("mediaSession" in navigator)) return;

        const t = currentTrack();
        if (!t) return;

        const title = t.name || String(t.path || "").split("/").pop() || "NeonWave";
        const artist = "NeonWave";
        const album = String(t.path || "").split("/").slice(-2, -1)[0] || "DNA-Nexus";

        const artwork = [];
        if (t.cover) {
            const url = coverUrl(t.cover);
            artwork.push(
                { src: url, sizes: "96x96", type: "image/jpeg" },
                { src: url, sizes: "256x256", type: "image/jpeg" },
                { src: url, sizes: "512x512", type: "image/jpeg" }
            );
        }

        try {
            navigator.mediaSession.metadata = new MediaMetadata({
                title,
                artist,
                album,
                artwork
            });
        } catch {
            // Some browsers are picky about artwork/type.
            try {
                navigator.mediaSession.metadata = new MediaMetadata({
                    title,
                    artist,
                    album
                });
            } catch {
                // Ignore unsupported MediaMetadata.
            }
        }
    }

    function installMediaSessionHandlers() {
        if (!("mediaSession" in navigator)) return;

        const handlers = {
            play: () => audio?.play().catch(() => {}),
            pause: () => audio?.pause(),
            previoustrack: previousTrack,
            nexttrack: nextTrack,
            seekbackward: () => seekBy(-10),
            seekforward: () => seekBy(10)
        };

        for (const [name, fn] of Object.entries(handlers)) {
            try {
                navigator.mediaSession.setActionHandler(name, fn);
            } catch {
                // Browser may not support all actions.
            }
        }
    }

    function installKeyboardShortcuts() {
        document.addEventListener("keydown", (ev) => {
            if (typingTarget(ev)) return;

            if (ev.code === "Space") {
                ev.preventDefault();
                playPause();
                return;
            }

            if (ev.key === "n" || ev.key === "N") {
                ev.preventDefault();
                nextTrack();
                return;
            }

            if (ev.key === "p" || ev.key === "P") {
                ev.preventDefault();
                previousTrack();
                return;
            }

            if (ev.key === "ArrowRight") {
                ev.preventDefault();
                seekBy(10);
                return;
            }

            if (ev.key === "ArrowLeft") {
                ev.preventDefault();
                seekBy(-10);
                return;
            }

            if (ev.key === "ArrowUp") {
                ev.preventDefault();
                volumeBy(0.05);
                return;
            }

            if (ev.key === "ArrowDown") {
                ev.preventDefault();
                volumeBy(-0.05);
            }
        });
    }

    function init() {
        audio = el("audio");
        if (!audio) return;

        installKeyboardShortcuts();
        installMediaSessionHandlers();

        audio.addEventListener("play", updateMediaSession);
        audio.addEventListener("loadedmetadata", updateMediaSession);

        window.PQNAS_NEONWAVE_MEDIA_KEYS = {
            update: updateMediaSession,
            next: nextTrack,
            previous: previousTrack,
            playPause
        };
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", init, { once: true });
    } else {
        init();
    }
})();