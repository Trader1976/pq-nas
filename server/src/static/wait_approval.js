(() => {
    const qs = new URLSearchParams(location.search);
    const sid = (qs.get("sid") || "").trim();

    const sidEl = document.getElementById("sid");
    const statusText = document.getElementById("statusText");
    const statusPill = document.getElementById("statusPill");
    const mainPill = document.getElementById("mainPill");

    function setPill(pill, kind, text) {
        if (!pill) return;
        pill.className = "pill " + (kind || "");
        const v = pill.querySelector(".v");
        if (v) v.textContent = text;
    }

    function setText(msg) {
        if (statusText) statusText.textContent = msg;
    }

    if (sidEl) sidEl.textContent = sid || "(missing sid)";

    if (!sid) {
        setPill(statusPill, "fail", "missing sid");
        setPill(mainPill, "fail", "error");
        setText("Missing sid in URL. Go back and start a new sign-in.");
        return;
    }

    async function pollOnce() {
        try {
            setPill(statusPill, "warn", "checking…");
            setText("Checking /api/v4/status…");

            const r = await fetch(`/api/v4/status?sid=${encodeURIComponent(sid)}`, {
                cache: "no-store",
                credentials: "include",
            });

            const j = await r.json().catch(() => ({}));

            if (!r.ok || !j.ok) {
                setPill(statusPill, "fail", "error");
                setPill(mainPill, "fail", "error");
                setText(`Status error: ${j.message || j.error || ("HTTP " + r.status)}`);
                return;
            }

            if (j.expired) {
                setPill(statusPill, "fail", "expired");
                setPill(mainPill, "fail", "expired");
                setText("This sign-in request expired. Go back and start again.");
                return;
            }

            if (j.approved) {
                setPill(statusPill, "ok", "approved");
                setPill(mainPill, "ok", "approved");
                setText("Approved ✔ Finalizing sign-in…");

                // turn approval into real cookie
                const cres = await fetch("/api/v4/consume", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ sid }),
                    cache: "no-store",
                    credentials: "include",
                });

                const cj = await cres.json().catch(() => ({}));
                if (!cres.ok || !cj.ok) {
                    setPill(statusPill, "fail", "cookie failed");
                    setPill(mainPill, "fail", "error");
                    setText(`Approved, but cookie set failed: ${cj.message || cj.error || ("HTTP " + cres.status)}`);
                    return;
                }

                location.href = "/success";
                return;
            }

            // pending (default)
            if (j.pending_admin) {
                setPill(statusPill, "warn", "pending");
                setPill(mainPill, "warn", "pending");
                setText("Waiting for admin approval…");
            } else {
                // server might not implement pending_admin -> still show correct message
                setPill(statusPill, "warn", "waiting");
                setPill(mainPill, "warn", "waiting");
                setText("Waiting for admin approval…");
            }
        } catch (e) {
            setPill(statusPill, "fail", "network");
            setPill(mainPill, "fail", "network");
            setText("Network error while checking approval status.");
        }
    }

    pollOnce();
    (function loop() {
        pollOnce().finally(() => setTimeout(loop, 1200));
    })();
})();
