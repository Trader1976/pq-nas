(() => {
    const statusEl = document.getElementById("status");
    const sidEl = document.getElementById("sid");
    const qrUriEl = document.getElementById("qruri");
    const qrImg = document.getElementById("qrimg");

    const btnCopySid = document.getElementById("copySid");
    const btnCopyQr = document.getElementById("copyQr");
    const btnNew = document.getElementById("newSession");

    let current = { sid: "", qr_uri: "", st: "" };
    let pollTimer = null;
    let stopped = false;

    function setStatus(s) {
        if (statusEl) statusEl.textContent = s;
    }

    function stop() {
        stopped = true;
        if (pollTimer) clearInterval(pollTimer);
        pollTimer = null;
    }

    async function consumeApproval() {
        // This is what actually sets the cookie in the browser.
        const r = await fetch("/api/v4/consume", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            cache: "no-store",
            body: JSON.stringify({ sid: current.sid }),
        });

        const txt = await r.text();
        if (!r.ok) {
            console.error("consume failed:", r.status, txt);
            throw new Error("consume failed HTTP " + r.status);
        }
        return txt ? JSON.parse(txt) : { ok: true };
    }

    async function pollStatusOnce() {
        if (stopped || !current.sid) return;

        try {
            const r = await fetch("/api/v4/status?sid=" + encodeURIComponent(current.sid), { cache: "no-store" });
            const txt = await r.text();
            if (!r.ok) {
                console.error("status error:", r.status, txt);
                setStatus("Status error HTTP " + r.status);
                return;
            }

            const j = JSON.parse(txt);
            if (j.approved) {
                stop();
                setStatus("Approved ✔ Finalizing session…");

                // ✅ IMPORTANT: set cookie in browser by consuming approval
                await consumeApproval();

                setStatus("Signed in ✔ Redirecting…");
                window.location.href = "/success";
                return;
            }

            if (j.expired) {
                stop();
                setStatus("Approval expired — start new session");
                return;
            }

            setStatus("Waiting for approval…");
        } catch (e) {
            console.error("pollStatusOnce failed:", e);
            setStatus("Polling error (see console)");
        }
    }

    async function issueSession() {
        stopped = false;
        if (pollTimer) clearInterval(pollTimer);
        pollTimer = null;

        setStatus("Issuing session…");

        try {
            const r = await fetch("/api/v4/session", { method: "POST", cache: "no-store" });
            const txt = await r.text();
            if (!r.ok) {
                console.error("session error:", r.status, txt);
                setStatus("Session error HTTP " + r.status);
                return;
            }

            const j = JSON.parse(txt);
            const sid = (j.sid || "").trim();
            const qr_uri = (j.qr_uri || "").trim();
            const st = (j.st || "").trim();

            if (!sid || !qr_uri || !st) {
                console.error("bad session json:", j);
                setStatus("Bad session response (missing sid/qr_uri/st)");
                return;
            }

            current = { sid, qr_uri, st };

            if (sidEl) sidEl.textContent = sid;
            if (qrUriEl) qrUriEl.value = qr_uri;

            if (qrImg) {
                qrImg.src = "/api/v4/qr.svg?st=" + encodeURIComponent(st);
            }

            setStatus("Waiting for approval… (scan QR)");
            await pollStatusOnce();
            pollTimer = setInterval(pollStatusOnce, 1000);
        } catch (e) {
            console.error("issueSession failed:", e);
            setStatus("Error: " + e);
        }
    }

    btnCopySid?.addEventListener("click", async () => {
        try { await navigator.clipboard.writeText(current.sid || ""); } catch {}
    });
    btnCopyQr?.addEventListener("click", async () => {
        try { await navigator.clipboard.writeText(current.qr_uri || ""); } catch {}
    });
    btnNew?.addEventListener("click", () => issueSession());

    issueSession();
})();
