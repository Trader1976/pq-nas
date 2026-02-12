(() => {
    "use strict";

    try {
        if (window.self !== window.top) document.body.classList.add("embedded");
    } catch (_) {
        document.body.classList.add("embedded");
    }

    const appVersionEl = el("appVersion");

    (async () => {
        if (!appVersionEl) return;
        try {
            // manifest.json is one level above /www/
            const r = await fetch("../manifest.json", { cache: "no-store" });
            const j = await r.json().catch(() => ({}));
            const ver = (j && typeof j.version === "string") ? j.version.trim() : "";
            if (ver) appVersionEl.textContent = "v" + ver;
        } catch (_) {
            // keep empty if not available
        }
    })();

    const badge = el("badge");
    const status = el("status");

    const volList = el("volList");
    const snapList = el("snapList");
    const volHint = el("volHint");
    const snapHint = el("snapHint");

    const detailsBtn = el("detailsBtn");
    const restoreBtn = el("restoreBtn");

    let volumes = [];
    let selectedVol = null;   // {name, source_subvolume, snap_root, enabled}
    let snapshots = [];
    let selectedSnap = null;  // {id, path, created_utc, readonly}
    let lastSnapListMeta = null; // { snap_root, volume, count }

    function setBadge(kind, text) {
        badge.className = `badge ${kind}`;
        badge.textContent = text;
    }

    async function apiGet(path) {
        const r = await fetch(path, {
            method: "GET",
            credentials: "include",
            cache: "no-store",
            headers: { "Accept": "application/json" }
        });
        const j = await r.json().catch(() => ({}));
        if (!r.ok || !j.ok) throw new Error(j.message || j.error || `HTTP ${r.status}`);
        return j;
    }

    async function apiPost(path, body) {
        const r = await fetch(path, {
            method: "POST",
            credentials: "include",
            cache: "no-store",
            headers: { "Content-Type": "application/json", "Accept": "application/json" },
            body: JSON.stringify(body || {})
        });
        const j = await r.json().catch(() => ({}));
        if (!r.ok || !j.ok) throw new Error(j.message || j.error || `HTTP ${r.status}`);
        return j;
    }

    function clearChildren(x) { while (x.firstChild) x.removeChild(x.firstChild); }

    function row(textTopLeft, textTopRight, textSub, isSel) {
        const d = document.createElement("div");
        d.className = "row" + (isSel ? " sel" : "");

        const top = document.createElement("div");
        top.className = "top";

        const a = document.createElement("div");
        a.textContent = textTopLeft || "";

        const b = document.createElement("div");
        b.className = "mono";
        b.style.opacity = "0.85";
        b.textContent = textTopRight || "";

        top.appendChild(a);
        top.appendChild(b);

        const sub = document.createElement("div");
        sub.className = "sub mono";
        sub.textContent = textSub || "";

        d.appendChild(top);
        d.appendChild(sub);
        return d;
    }

    function updateButtons() {
        const hasVol = !!selectedVol;
        const hasSnap = !!selectedSnap;
        const isSub = !!(selectedSnap && selectedSnap.is_btrfs_subvolume === true);
        const probe = String((selectedSnap && selectedSnap.probe) || "ok");

        detailsBtn.disabled = !hasSnap;
        restoreBtn.disabled = !(hasVol && hasSnap && isSub && probe !== "no_privs");
    }



    function renderVolumes() {
        clearChildren(volList);
        volHint.textContent = volumes.length ? `${volumes.length}` : "";

        for (const v of volumes) {
            const isSel = selectedVol && selectedVol.name === v.name;
            const d = row(
                v.name,
                v.enabled ? "enabled" : "disabled",
                `${v.source_subvolume}  |  ${v.snap_root}`,
                isSel
            );
            d.addEventListener("click", () => {
                selectedVol = v;
                selectedSnap = null;
                renderVolumes();
                loadSnapshotsForSelectedVol();
            });
            volList.appendChild(d);
        }
    }

    function renderSnapshots() {
        clearChildren(snapList);
        snapHint.textContent = snapshots.length ? `${snapshots.length}` : "";

        for (let i = 0; i < snapshots.length; i++) {
            const s = snapshots[i];
            const isSel = selectedSnap && selectedSnap.id === s.id;

            const isSub = (s.is_btrfs_subvolume === true);
            const probe = String(s.probe || "ok");
            const isLatest = (i === 0 && isSub); // list is already sorted newest-first

            // Right-side label logic
            let right = "";
            if (isLatest) right = "latest";
            else if (probe === "no_privs") right = "no-privs";
            else if (!isSub) right = "junk";
            else right = (s.readonly ? "ro" : "rw");

            const sub = s.created_utc || s.path || "";

            const d = row(s.id, right, sub, isSel);

            // Visual cue for non-subvol / no-privs
            if (!isSub) d.style.opacity = "0.70";
            if (probe === "no_privs") d.style.opacity = "0.75";

            d.addEventListener("click", () => {
                selectedSnap = s;
                renderSnapshots();
                updateButtons();

                if (probe === "no_privs") {
                    status.textContent = `Selected: ${s.id} (cannot verify btrfs subvolume; sudo rule missing)`;
                } else if (!isSub) {
                    status.textContent = `Selected: ${s.id} (NOT a btrfs snapshot subvolume)`;
                } else {
                    status.textContent = `Selected snapshot: ${s.id}`;
                }
            });

            snapList.appendChild(d);
        }

        if (!snapshots.length) {
            const d = row("(no snapshots found)", "", "Check snap_root path and snapshot runner output.", false);
            d.style.cursor = "default";
            snapList.appendChild(d);
        }
    }



    async function loadVolumes() {
        setBadge("warn", "loading…");
        status.textContent = "Loading volumes…";

        const j = await apiGet("/api/v4/snapshots/volumes");
        volumes = Array.isArray(j.volumes) ? j.volumes : [];
        volumes.sort((a, b) => String(a.name).localeCompare(String(b.name)));

        if (!selectedVol && volumes.length) selectedVol = volumes[0];

        renderVolumes();
        setBadge("ok", "ready");
        status.textContent = "Volumes loaded.";
    }

    async function loadSnapshotsForSelectedVol() {
        updateButtons();

        if (!selectedVol) {
            snapshots = [];
            renderSnapshots();
            return;
        }

        setBadge("warn", "loading…");
        status.textContent = `Loading snapshots for ${selectedVol.name}…`;

        const qs = new URLSearchParams({ volume: selectedVol.name });
        const j = await apiGet(`/api/v4/snapshots/list?${qs.toString()}`);

        snapshots = Array.isArray(j.snapshots) ? j.snapshots : [];
        lastSnapListMeta = {
            volume: j.volume || selectedVol.name,
            snap_root: j.snap_root || selectedVol.snap_root || "",
            count: snapshots.length
        };
        renderSnapshots();
        if (!selectedSnap && snapshots.length) {
            selectedSnap = snapshots[0]; // list is already newest-first server-side
            renderSnapshots();
        }


        setBadge("ok", "ready");
        status.textContent = `Snapshots loaded for ${selectedVol.name}.`;
        updateButtons();
    }

    async function showDetails() {
        if (!selectedVol || !selectedSnap) return;
        try {
            setBadge("warn", "loading…");
            status.textContent = "Loading details…";
            const qs = new URLSearchParams({ volume: selectedVol.name, id: selectedSnap.id });
            const j = await apiGet(`/api/v4/snapshots/info?${qs.toString()}`);

            if (j && j.btrfs_show_ok === false) {
                // clean user-facing warning (no giant blob)
                alert(
                    `Snapshot details require sudo/root on this host.\n\n` +
                    `btrfs_show_rc=${j.btrfs_show_rc}\n` +
                    `${j.hint ? "\n" + j.hint : ""}\n\n` +
                    `Raw output:\n${j.btrfs_show || ""}`
                );
            } else {
                alert(JSON.stringify(j, null, 2));
            }

            setBadge("ok", "ready");
            status.textContent = "Ready.";
        } catch (e) {
            setBadge("err", "error");
            status.textContent = `Details failed: ${String(e && e.message ? e.message : e)}`;
        }
    }

    async function doRestore() {
        if (!selectedVol || !selectedSnap) return;

        const vol = selectedVol.name;
        const id = selectedSnap.id;

        const phrase = `RESTORE ${vol} ${id}`;

        const ok1 = confirm(
            `Restore snapshot?\n\nVolume: ${vol}\nSnapshot: ${id}\n\n` +
            `This will REPLACE the live volume content.\nDowntime required.`
        );
        if (!ok1) return;

        const typed = prompt(
            `Type the confirmation phrase EXACTLY to continue:\n\n${phrase}`,
            ""
        );
        if (typed !== phrase) {
            status.textContent = "Restore canceled (confirmation text did not match).";
            return;
        }

        setBadge("warn", "working…");
        status.textContent = "Preparing restore…";

        try {
            const prep = await apiPost("/api/v4/snapshots/restore/prepare", {
                volume: vol,
                id,
                mode: "swap",
                force_stop: true
            });

            // Optional: show the plan before final confirm
            const planText = JSON.stringify(prep.plan || {}, null, 2);
            const ok2 = confirm(`Restore plan:\n\n${planText}\n\nProceed now?`);
            if (!ok2) {
                setBadge("ok", "ready");
                status.textContent = "Restore canceled.";
                return;
            }

            setBadge("warn", "working…");
            status.textContent = "Restoring…";

            await apiPost("/api/v4/snapshots/restore/confirm", {
                confirm_id: prep.confirm_id,
                confirm_text: phrase
            });

            setBadge("ok", "done");
            status.textContent = `Restored ${vol} to ${id}. Refreshing…`;

            selectedSnap = null;
            await loadSnapshotsForSelectedVol();

        } catch (e) {
            setBadge("err", "error");
            status.textContent = `Restore failed: ${String(e && e.message ? e.message : e)}`;
        } finally {
            updateButtons();
        }
    }

    async function loadAll() {
        try {
            await loadVolumes();
            await loadSnapshotsForSelectedVol();
            updateButtons();
        } catch (e) {
            setBadge("err", "error");
            status.textContent = String(e && e.message ? e.message : e);
        }
    }


    detailsBtn?.addEventListener("click", showDetails);
    restoreBtn?.addEventListener("click", doRestore);

    loadAll();
})();
