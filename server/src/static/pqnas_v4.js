(() => {
    const statusEl = document.getElementById("status");
    const sidEl = document.getElementById("sid");
    const qrUriEl = document.getElementById("qruri");

    let sid = null;
    let stopped = false;

    function setStatus(msg) {
        if (statusEl) statusEl.textContent = msg;
    }

    async function createSession() {
        setStatus("Creating session…");

        const r = await fetch("/api/v4/session", {
            method: "POST",
            cache: "no-store",
            headers: { "Content-Type": "application/json" },
            body: "{}",
        });

        if (!r.ok) {
            setStatus("Error issuing session: HTTP " + r.status);
            return null;
        }

        const j = await r.json();
        sid = (j.sid || "").trim();

        if (sidEl) sidEl.textContent = sid || "(no sid)";
        if (qrUriEl) qrUriEl.value = j.qr_uri || "(no qr_uri)";

        setStatus("Waiting for approval…");
        return j;
    }

    async function pollOnce() {
        if (stopped || !sid) return;

        const r = await fetch(`/api/v4/status?sid=${encodeURIComponent(sid)}`, { cache: "no-store" });
        if (!r.ok) {
            setStatus("Server error (status)");
            return;
        }

        const j = await r.json();
        if (j.expired) {
            stopped = true;
            setStatus("Expired — refresh page");
            return;
        }

        if (j.approved) {
            stopped = true;
            setStatus("Approved ✔ Finalizing…");

            const c = await fetch("/api/v4/consume", {
                method: "POST",
                cache: "no-store",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ sid }),
            });

            if (!c.ok) {
                setStatus("Finalize failed (consume)");
                return;
            }

            window.location.href = "/success";
            return;
        }

        setStatus("Waiting for approval…");
    }

    async function main() {
        await createSession();
        pollOnce();
        const t = setInterval(() => {
            if (stopped) return clearInterval(t);
            pollOnce();
        }, 1000);
    }

    main().catch(e => setStatus("Error: " + e));
})();
