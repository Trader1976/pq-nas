(() => {
    const el = (id) => document.getElementById(id);

    const statusEl = el("status");
    const sidEl = el("sid");
    const qrImg = el("qrimg");
    const qrUriTa = el("qruri");

    const copySidBtn = el("copySid");
    const copyQrBtn = el("copyQr");
    const newBtn = el("newSession");

    let stopped = false;
    let sid = "";
    let st = "";
    let expiresAt = 0; // epoch seconds
    let countdownTimer = null;
    let pollTimer = null;

    // ---------- UI helpers ----------
    function setStatus(msg) {
        if (statusEl) statusEl.textContent = msg;
    }

    function setBusy(isBusy) {
        document.body.classList.toggle("busy", !!isBusy);
    }

    function fmtMMSS(secs) {
        secs = Math.max(0, Math.floor(secs));
        const m = Math.floor(secs / 60);
        const s = secs % 60;
        return `${m}:${String(s).padStart(2, "0")}`;
    }

    async function copyText(text) {
        try {
            await navigator.clipboard.writeText(text);
            setStatus("Copied ✔");
            setTimeout(() => setStatus("Waiting for approval…"), 800);
        } catch {
            setStatus("Copy failed (browser permission)");
        }
    }

    // ---------- core flow ----------
    async function issueSession() {
        stopped = false;
        sid = "";
        st = "";
        expiresAt = 0;

        if (sidEl) sidEl.textContent = "(issuing…)";
        if (qrUriTa) qrUriTa.value = "(loading…)";
        if (qrImg) qrImg.removeAttribute("src");

        clearInterval(countdownTimer);
        clearInterval(pollTimer);

        setBusy(true);
        setStatus("Issuing session…");

        const r = await fetch("/api/v4/session", { method: "POST", cache: "no-store" });
        if (!r.ok) {
            setBusy(false);
            setStatus("Error issuing session: HTTP " + r.status);
            return;
        }

        const j = await r.json();

        sid = (j.sid || "").trim();
        st = (j.st || "").trim();
        expiresAt = Number(j.expires_at || 0);

        if (sidEl) sidEl.textContent = sid || "(no sid)";
        if (qrUriTa) qrUriTa.value = (j.qr_uri || "").trim();

        // Render server-side SVG QR (you already have /api/v4/qr.svg?st=...)
        if (qrImg && st) {
            qrImg.src = "/api/v4/qr.svg?st=" + encodeURIComponent(st) + "&_=" + Date.now();
        }

        setBusy(false);
        setStatus("Waiting for approval…");

        startCountdown();
        startPolling();
    }

    function startCountdown() {
        if (!expiresAt) return;

        const tick = () => {
            if (stopped) return;

            const now = Math.floor(Date.now() / 1000);
            const left = expiresAt - now;

            // If you want the countdown visible in the status text:
            if (left > 0) {
                setStatus(`Waiting for approval… (expires in ${fmtMMSS(left)})`);
            } else {
                stopped = true;
                setStatus("Expired. Creating a new session…");
                // auto-refresh after a short pause
                setTimeout(() => issueSession().catch(console.error), 900);
            }
        };

        tick();
        countdownTimer = setInterval(tick, 250);
    }

    function startPolling() {
        if (!sid) return;

        const pollOnce = async () => {
            if (stopped) return;

            try {
                const res = await fetch(`/api/v4/status?sid=${encodeURIComponent(sid)}`, { cache: "no-store" });
                if (!res.ok) return; // transient

                const data = await res.json();
                // expected: {ok:true, approved:true/false, expired?:true}
                if (data && data.approved) {
                    stopped = true;
                    setBusy(true);
                    setStatus("Approved ✔ Finalizing…");

                    // Convert approval into real browser cookie
                    const cres = await fetch("/api/v4/consume", {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({ sid }),
                        cache: "no-store",
                    });

                    if (!cres.ok) {
                        setBusy(false);
                        setStatus("Approved, but cookie set failed (HTTP " + cres.status + ")");
                        return;
                    }

                    // Redirect only after cookie has been set
                    window.location.href = "/success";
                    return;
                }

                if (data && data.expired) {
                    stopped = true;
                    setStatus("Expired. Creating a new session…");
                    setTimeout(() => issueSession().catch(console.error), 900);
                    return;
                }
            } catch (e) {
                // ignore transient network errors, keep polling
                console.debug("poll error", e);
            }
        };

        pollOnce();
        pollTimer = setInterval(pollOnce, 900);
    }

    // ---------- button wiring ----------
    if (copySidBtn) {
        copySidBtn.addEventListener("click", () => {
            if (!sid) return setStatus("No sid yet");
            copyText(sid);
        });
    }

    if (copyQrBtn) {
        copyQrBtn.addEventListener("click", () => {
            const t = qrUriTa ? qrUriTa.value : "";
            if (!t || t.startsWith("(")) return setStatus("No QR payload yet");
            copyText(t);
        });
    }

    if (newBtn) {
        newBtn.addEventListener("click", () => {
            issueSession().catch(console.error);
        });
    }

    // Start immediately
    issueSession().catch((e) => {
        console.error(e);
        setBusy(false);
        setStatus("Error: " + e);
    });
})();
