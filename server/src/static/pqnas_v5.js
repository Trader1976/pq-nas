(() => {
    "use strict";

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
    let k = "";             // NEW: sha256(st) base64, poll key for 2A
    let st = "";
    let expiresAt = 0;
    let countdownTimer = null;
    let pollTimer = null;

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

    function clearTimers() {
        if (countdownTimer) clearInterval(countdownTimer);
        if (pollTimer) clearInterval(pollTimer);
        countdownTimer = null;
        pollTimer = null;
    }

    function setQrFromResponse(j) {
        if (qrImg) {
            if (j && typeof j.qr_svg === "string" && j.qr_svg.trim().startsWith("<svg")) {
                const svg = j.qr_svg.trim();
                const blob = new Blob([svg], { type: "image/svg+xml" });
                const url = URL.createObjectURL(blob);
                qrImg.src = url;
                return;
            }

            if (j && typeof j.qr_url === "string" && j.qr_url.trim()) {
                qrImg.src = j.qr_url.trim() + (j.qr_url.includes("?") ? "&" : "?") + "_=" + Date.now();
                return;
            }

            if (st) {
                qrImg.src = "/api/v5/qr.svg?st=" + encodeURIComponent(st) + "&_=" + Date.now();
                return;
            }
        }
    }

    async function issueSession() {
        stopped = false;
        sid = "";
        k = "";
        st = "";
        expiresAt = 0;

        if (sidEl) sidEl.textContent = "(issuing…)";
        if (qrUriTa) qrUriTa.value = "(loading…)";
        if (qrImg) qrImg.removeAttribute("src");

        clearTimers();

        setBusy(true);
        setStatus("Issuing v5 session…");

        let r;
        try {
            r = await fetch("/api/v5/session", {
                method: "POST",
                cache: "no-store",
                credentials: "include",
            });

        } catch (e) {
            setBusy(false);
            setStatus("Network error issuing v5 session");
            console.error(e);
            return;
        }

        let j = {};
        try { j = await r.json(); } catch {}

        if (!r.ok || !j || j.ok === false) {
            setBusy(false);
            const msg = (j && j.message) ? String(j.message) : ("HTTP " + r.status);
            setStatus("v5 session not available: " + msg);
            return;
        }

        sid = String(j.sid || "").trim();                 // optional
        k   = String(j.k || "").trim();                   // preferred poll key (2A)
        st  = String(j.st || j.req || "").trim();
        expiresAt = Number(j.expires_at || j.exp || 0);

        if (sidEl) sidEl.textContent = (k ? `k:${k.slice(0,10)}…` : (sid || "(no sid)"));
        if (qrUriTa) qrUriTa.value = String(j.qr_uri || "").trim() || "(no qr_uri)";

        setQrFromResponse(j);

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

            if (left > 0) {
                setStatus(`Waiting for approval… (expires in ${fmtMMSS(left)})`);
            } else {
                stopped = true;
                setStatus("Expired. Creating a new session…");
                setTimeout(() => issueSession().catch(console.error), 900);
            }
        };

        tick();
        countdownTimer = setInterval(tick, 250);
    }

    function startPolling() {

        const statusBody = () => {
            if (k) return { k };
            if (st) return { st };
            if (sid) return { sid };
            return null;
        };

        if (!statusBody()) {
            setStatus("Server returned no k/st/sid (v5 session incomplete).");
            return;
        }

        const pollOnce = async () => {
            if (stopped) return;

            try {
                const res = await fetch("/api/v5/status", {
                    method: "POST",
                    cache: "no-store",
                    credentials: "include",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify(statusBody()),
                });
                if (!res.ok) return;

                const data = await res.json().catch(() => ({}));

// Helpful debug while we lock this down
// console.debug("[v5-login] status", data);

// Approved → consume
                if (data && data.approved === true) {
                    stopped = true;
                    setBusy(true);
                    setStatus("Approved ✔ Finalizing (consume)…");

                    const body = k ? { k } : (st ? { st } : { sid });

                    const cres = await fetch("/api/v5/consume", {
                        method: "POST",
                        cache: "no-store",
                        credentials: "include",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify(body),
                    });

                    if (!cres.ok) {
                        setBusy(false);
                        setStatus("Failed to finalize session (consume): HTTP " + cres.status);
                        return;
                    }

                    const ping = await fetch("/api/v4/me", {
                        cache: "no-store",
                        credentials: "include",
                    });


                    if (!ping.ok) {
                        setBusy(false);
                        setStatus("Consume OK, but cookie did not stick (auth check failed): HTTP " + ping.status);
                        return;
                    }

                    // Go to the app, not /success (unless you actually have a success page)
                    window.location.href = "/app";
                    return;
                }


// Pending: if this is admin approval flow, redirect to wait page
                if (data && data.state === "pending") {
                    if (data.reason === "pending_admin" || data.reason === "awaiting_approval") {
                        stopped = true;
                        setBusy(false);
                        setStatus("Not approved yet — waiting for admin approval.");
                        const qk = k || "";
                        const qst = (!qk && st) ? st : "";
                        window.location.href = qk
                            ? ("/wait-approval?k=" + encodeURIComponent(qk))
                            : ("/wait-approval?st=" + encodeURIComponent(qst));

                        return;
                    }
                    // otherwise keep polling silently
                    return;
                }


// Missing: server doesn't know this k anymore (pruned / never stored) → re-issue
                if (data && data.state === "missing") {
                    stopped = true;
                    setStatus("Session lost. Creating a new session…");
                    setTimeout(() => issueSession().catch(console.error), 900);
                    return;
                }

            } catch (e) {
                console.debug("v5 poll error", e);
            }
        };

        pollOnce();
        pollTimer = setInterval(pollOnce, 900);
    }

    if (copySidBtn) {
        copySidBtn.addEventListener("click", () => {
            const t = k || sid;
            if (!t) return setStatus("No k/sid yet");
            copyText(t);
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

    issueSession().catch((e) => {
        console.error(e);
        setBusy(false);
        setStatus("Error: " + e);
    });
})();
