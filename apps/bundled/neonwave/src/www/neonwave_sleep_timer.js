(() => {
    "use strict";

    const el = (id) => document.getElementById(id);

    let audio = null;
    let stateEl = null;
    let stopBtn = null;
    let trackBtn = null;

    let timerId = null;
    let deadlineMs = 0;
    let endOfTrack = false;

    function appApi() {
        return window.PQNAS_NEONWAVE_APP || null;
    }

    function setStatus(msg) {
        const api = appApi();
        if (api && typeof api.setStatus === "function") {
            api.setStatus(msg);
            return;
        }

        const statusLine = el("statusLine");
        if (statusLine) statusLine.textContent = msg;
    }

    function fmtRemaining(ms) {
        const sec = Math.max(0, Math.ceil(ms / 1000));
        const m = Math.floor(sec / 60);
        const s = sec % 60;

        if (m <= 0) return `${s}s`;
        return `${m}:${String(s).padStart(2, "0")}`;
    }

    function renderState(text, active) {
        if (!stateEl) return;
        stateEl.textContent = text;
        stateEl.classList.toggle("active", !!active);
    }

    function clearSleepTimer(opts = {}) {
        if (timerId) {
            window.clearInterval(timerId);
            timerId = null;
        }

        deadlineMs = 0;
        endOfTrack = false;

        renderState("Off", false);

        if (!opts.silent) {
            setStatus("Sleep timer off.");
        }
    }

    function stopPlayback(reason) {
        if (audio) {
            audio.pause();
        }

        clearSleepTimer({ silent: true });
        setStatus(reason || "Sleep timer stopped playback.");
    }

    function tick() {
        if (!deadlineMs) return;

        const left = deadlineMs - Date.now();

        if (left <= 0) {
            stopPlayback("Sleep timer stopped playback.");
            return;
        }

        renderState(fmtRemaining(left), true);
    }

    function startMinutes(minutes) {
        minutes = Number(minutes);
        if (!Number.isFinite(minutes) || minutes <= 0) return;

        clearSleepTimer({ silent: true });

        deadlineMs = Date.now() + minutes * 60 * 1000;
        endOfTrack = false;

        tick();
        timerId = window.setInterval(tick, 1000);

        setStatus(`Sleep timer set for ${minutes} minutes.`);
    }

    function startEndOfTrack() {
        if (!audio || !audio.src) {
            setStatus("Start a track first, then enable end-of-track sleep.");
            return;
        }

        clearSleepTimer({ silent: true });

        endOfTrack = true;
        deadlineMs = 0;

        renderState("End of track", true);
        setStatus("Sleep timer will stop at the end of this track.");
    }

    function handleEnded(ev) {
        if (!endOfTrack) return;

        // Stop NeonWave's normal auto-next handler from advancing the queue.
        if (ev && typeof ev.stopImmediatePropagation === "function") {
            ev.stopImmediatePropagation();
        }

        stopPlayback("Sleep timer stopped at end of track.");
    }

    function init() {
        audio = el("audio");
        stateEl = el("sleepState");
        stopBtn = el("sleepStopBtn");
        trackBtn = el("sleepTrackBtn");

        if (!audio || !stateEl) return;

        document.querySelectorAll("[data-sleep-min]").forEach((btn) => {
            btn.addEventListener("click", () => {
                startMinutes(btn.getAttribute("data-sleep-min"));
            });
        });

        trackBtn?.addEventListener("click", startEndOfTrack);
        stopBtn?.addEventListener("click", () => clearSleepTimer());

        // Capture phase helps us stop NeonWave auto-next when sleep mode is "end of track".
        audio.addEventListener("ended", handleEnded, true);

        audio.addEventListener("play", () => {
            if (deadlineMs) tick();
        });

        renderState("Off", false);

        window.PQNAS_NEONWAVE_SLEEP = {
            startMinutes,
            startEndOfTrack,
            clear: clearSleepTimer
        };
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", init, { once: true });
    } else {
        init();
    }
})();