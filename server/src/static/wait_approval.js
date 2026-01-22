(() => {
    const qs = new URLSearchParams(location.search);
    const sid = (qs.get("sid") || "").trim();

    const sidEl = document.getElementById("sid");
    const statusEl = document.getElementById("status");

    function setStatus(msg) {
        if (statusEl) statusEl.textContent = msg;
    }

    if (sidEl) sidEl.textContent = sid || "(missing sid)";
    if (!sid) {
        setStatus("Missing sid in URL. Go back and start a new sign-in.");
        return;
    }

    async function poll() {
        try {
            const r = await fetch(`/api/v4/status?sid=${encodeURIComponent(sid)}`, {
                cache: "no-store",
                credentials: "include",
            });

            const j = await r.json().catch(() => ({}));

            if (!r.ok || !j.ok) {
                setStatus(`Status error: ${j.message || j.error || ("HTTP " + r.status)}`);
                return;
            }

            if (j.approved) {
                setStatus("Approved ✔ Finalizing sign-in…");

                // turn approval into real cookie
                const cres = await fetch("/api/v4/consume", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ sid }),
                    cache: "no-store",
                });
                const cj = await cres.json().catch(() => ({}));

                if (!cres.ok || !cj.ok) {
                    setStatus(`Approved, but cookie set failed: ${cj.message || cj.error || ("HTTP " + cres.status)}`);
                    return;
                }

                location.href = "/success";
                return;
            }

            if (j.expired) {
                setStatus("This sign-in request expired. Go back and start again.");
                return;
            }

            // pending (default)
            if (j.pending_admin) {
                setStatus("Waiting for admin approval…");
            } else {
                // if server doesn’t implement pending_admin yet, still show a helpful message
                setStatus("Waiting for admin approval…");
            }
        } catch (e) {
            setStatus("Network error while checking approval status.");
        }
    }

    poll();
    async function loop() {
        await poll();
        setTimeout(loop, 1200);
    }
    loop();
})();
