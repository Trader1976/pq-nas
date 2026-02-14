(() => {
    "use strict";
    const el = (id) => document.getElementById(id);

    try {
        if (window.self !== window.top) document.body.classList.add("embedded");
    } catch (_) {
        document.body.classList.add("embedded");
    }

    const appVersionEl = el("appVersion");

    (async () => {
        if (!appVersionEl) return;
        const candidates = ["./manifest.json", "../manifest.json"];
        for (const url of candidates) {
            try {
                const r = await fetch(url, { cache: "no-store" });
                if (!r.ok) continue;
                const j = await r.json().catch(() => ({}));
                const ver = (j && typeof j.version === "string") ? j.version.trim() : "";
                if (ver) { appVersionEl.textContent = "v" + ver; return; }
            } catch (_) {}
        }
    })();


    const badge = el("badge");
    const status = el("status");
    const warnBanner = el("warnBanner");
// modal bits
    const modalOverlay = el("modalOverlay");
    const modalTitle = el("modalTitle");
    const modalBody = el("modalBody");
    const modalCloseBtn = el("modalCloseBtn");

    const volList = el("volList");
    const snapList = el("snapList");
    const volHint = el("volHint");
    const snapHint = el("snapHint");
    const refreshBtn = el("refreshBtn");
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
    function showBanner(html) {
        if (!warnBanner) return;
        if (!html) { warnBanner.style.display = "none"; warnBanner.innerHTML = ""; return; }
        warnBanner.innerHTML = html;
        warnBanner.style.display = "";
    }

    function openModal(title, html) {
        if (!modalOverlay || !modalBody || !modalTitle) {
            console.error("Modal DOM missing:", { modalOverlay, modalBody, modalTitle });
            return;
        }
        modalTitle.textContent = title || "Details";
        modalBody.innerHTML = html || "";
        modalOverlay.style.display = "flex";
        modalOverlay.setAttribute("aria-hidden", "false");
    }

    function closeModal() {
        if (!modalOverlay) return;
        modalOverlay.style.display = "none";
        modalOverlay.setAttribute("aria-hidden", "true");
        if (modalBody) modalBody.innerHTML = "";
    }

    modalCloseBtn?.addEventListener("click", closeModal);
    modalOverlay?.addEventListener("click", (e) => {
        if (e.target === modalOverlay) closeModal();
    });
    window.addEventListener("keydown", (e) => {
        if (e.key === "Escape") closeModal();
    });

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

    function sudoSetupHtml() {
        const user = window.__pqnasRuntimeUser || "<YOUR_USER>";

        return `
    <div style="font-weight:900; margin-bottom:8px;">Enable btrfs probing (no password prompt)</div>

    <div style="opacity:.9; margin-bottom:10px;">
      Snapshot Manager calls <span class="mono">sudo -n btrfs subvolume show ...</span>
      to verify that entries are real snapshots.
      If sudo requires a password, probing becomes <b>no-privs</b> and restore stays disabled.
    </div>

    <div style="font-weight:900; margin:12px 0 6px;">Recommended sudoers rule</div>

<pre class="mono">sudo visudo

# PQ-NAS running as:
${user}

${user} ALL=(root) NOPASSWD: /usr/bin/btrfs subvolume show *</pre>

    <div style="opacity:.9; margin-top:10px;">
      After saving sudoers, reload this page.
    </div>
  `;
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
            else if (probe === "no_privs") right = "⚠";
            else if (!isSub) right = "junk";
            else right = (s.readonly ? "ro" : "rw");

            const sub = s.created_utc || s.path || "";

            const d = row(s.id, right, sub, isSel);
            if (probe === "no_privs") d.classList.add("noPrivs");
            if (!isSub) d.classList.add("notSubvol");

// tooltip on right-side label
            const rightEl = d.querySelector(".top .mono");
            if (rightEl) {
                if (probe === "no_privs") {
                    rightEl.innerHTML = `<span class="pillWarn" title="No sudo privileges to verify btrfs subvolume (sudo -n failed)">⚠</span>`;
                } else if (!isSub) {
                    rightEl.title = "This folder is not a btrfs snapshot subvolume (junk under snap_root)";
                } else if (isLatest) {
                    rightEl.title = "Newest snapshot (server sorted newest-first)";
                }
            }

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

        // Store runtime user for sudo help modal
        window.__pqnasRuntimeUser =
            (j && typeof j.runtime_user === "string" && j.runtime_user.trim())
                ? j.runtime_user.trim()
                : "";

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


        const noPrivsCount = snapshots.filter(s => String(s.probe || "") === "no_privs").length;
        const junkCount = snapshots.filter(s => s.is_btrfs_subvolume !== true).length;

        if (noPrivsCount > 0) {
            showBanner(
                `⚠ Snapshot verification needs sudo privileges on this host. ` +
                `${noPrivsCount} item(s) could not be verified. ` +
                `<a href="#" id="sudoHelpLink">Show sudo setup</a>`
            );
            // link handler
            setTimeout(() => {
                const a = document.getElementById("sudoHelpLink");
                a?.addEventListener("click", (ev) => {
                    ev.preventDefault();
                    openModal("Sudo setup", sudoSetupHtml());
                });
            }, 0);
        } else if (junkCount > 0) {
            showBanner(`Note: ${junkCount} item(s) under snap_root are not btrfs snapshot subvolumes (junk folders).`);
        } else {
            showBanner("");
        }

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

            const raw = JSON.stringify(j, null, 2);

            const needsSudo =
                (j && typeof j.btrfs_show === "string" && j.btrfs_show.toLowerCase().includes("operation not permitted")) ||
                (selectedSnap && String(selectedSnap.probe || "") === "no_privs");

            if (needsSudo) {
                openModal(
                    `Snapshot details: ${selectedSnap.id}`,
                    `
      <div class="modalGrid">
        <div class="modalPanel">
          <h3><span class="warnIcon">⚠</span> Details require sudo privileges</h3>
          <div class="modalNote">
            Snapshot Manager calls <span class="mono">sudo -n btrfs subvolume show ...</span>.
            If sudo prompts for a password, probing becomes <b>no-privs</b> and restore stays disabled.
          </div>

          <div class="modalNote">
            <a href="#" id="sudoInlineLink">Show sudo setup instructions</a>
          </div>

          <div id="sudoBlock" style="display:none;">
            ${sudoSetupHtml()}
          </div>
        </div>

        <div class="modalPanel">
          <h3>Raw JSON</h3>
          <pre class="mono">${escapeHtml(raw)}</pre>
        </div>
      </div>
    `
                );

                setTimeout(() => {
                    const a = document.getElementById("sudoInlineLink");
                    const b = document.getElementById("sudoBlock");
                    a?.addEventListener("click", (ev) => {
                        ev.preventDefault();
                        if (!b) return;
                        const on = (b.style.display !== "none");
                        b.style.display = on ? "none" : "";
                        if (!on) b.scrollIntoView({ behavior: "smooth", block: "start" });
                    });
                }, 0);
            } else {
                openModal(
                    `Snapshot details: ${selectedSnap.id}`,
                    `<div class="modalGrid">
       <div class="modalPanel">
         <h3>Raw JSON</h3>
         <pre class="mono">${escapeHtml(raw)}</pre>
       </div>
     </div>`
                );
            }


            setBadge("ok", "ready");
            status.textContent = "Ready.";
        } catch (e) {
            setBadge("err", "error");
            status.textContent = `Details failed: ${String(e && e.message ? e.message : e)}`;
        }
    }

    function escapeHtml(s) {
        return String(s)
            .replaceAll("&", "&amp;")
            .replaceAll("<", "&lt;")
            .replaceAll(">", "&gt;")
            .replaceAll('"', "&quot;")
            .replaceAll("'", "&#39;");
    }


    async function doRestore() {
        if (!selectedVol || !selectedSnap) return;

        const vol = selectedVol.name;
        const id = selectedSnap.id;
        const isSub = (selectedSnap && selectedSnap.is_btrfs_subvolume === true);
        const probe = String((selectedSnap && selectedSnap.probe) || "ok");
        if (!isSub || probe === "no_privs") {
            status.textContent = "Restore disabled: snapshot not verified as a btrfs subvolume (or sudo missing).";
            return;
        }

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

            const done = await apiPost("/api/v4/snapshots/restore/confirm", {
                confirm_id: prep.confirm_id,
                confirm_text: phrase
            });
            // confirm starts an ASYNC systemd job now
            const jobId = String((done && done.job_id) || "");
            if (!jobId) throw new Error("Restore started but server did not return job_id");

            setBadge("warn", "restoring…");
            status.textContent = `Restoring… (job ${jobId})`;

            const pollEveryMs = 1200;
            const timeoutMs = 10 * 60 * 1000;
            const t0 = Date.now();

            while (true) {
                if (Date.now() - t0 > timeoutMs) {
                    throw new Error(`Restore timed out waiting for result (job ${jobId})`);
                }

                let st;
                try {
                    st = await apiGet(`/api/v4/snapshots/restore/status?job_id=${encodeURIComponent(jobId)}`);
                } catch (e) {
                    // transient polling error; retry
                    await new Promise(r => setTimeout(r, pollEveryMs));
                    continue;
                }

                // Compat: server may return wrapped {status,result} OR raw result JSON
                const hasWrapped = (st && typeof st.status === "string");
                const stStatus = hasWrapped
                    ? String(st.status || "unknown")
                    : (st && typeof st.step === "string") ? "done" : "unknown";

                const r = hasWrapped ? (st.result || null) : st;

// If we have a result (wrapped or raw), treat as done
                if (stStatus === "done" && r) {
                    const ok = !!r.ok;
                    const backupPath = (r && typeof r.backup_path === "string") ? r.backup_path : "";

                    setBadge(ok ? "ok" : "err", ok ? "done" : "failed");
                    status.textContent = ok
                        ? `✅ Restore completed for ${vol} → ${id}. Refreshing…`
                        : `❌ Restore failed for ${vol} → ${id}.`;

                    openModal(
                        ok ? "Restore completed" : "Restore failed",
                        `
<div class="modalGrid">
  <div class="modalPanel">
    <h3>${ok ? "Result" : "Error"}</h3>
    <div class="modalNote">Volume <b>${escapeHtml(vol)}</b> → snapshot <b>${escapeHtml(id)}</b></div>
    <div class="modalNote mono">job_id=${escapeHtml(jobId)}</div>
    ${backupPath ? `<div class="modalNote">Backup saved as:<br><span class="mono">${escapeHtml(backupPath)}</span></div>` : ""}
    ${!ok ? `<div class="modalNote">Step: <span class="mono">${escapeHtml(String(r.step || ""))}</span></div>
             <div class="modalNote">Error: <span class="mono">${escapeHtml(String(r.error || ""))}</span></div>` : ""}
  </div>
  <div class="modalPanel">
    <h3>Raw result JSON</h3>
    <pre class="mono">${escapeHtml(JSON.stringify(r, null, 2))}</pre>
  </div>
</div>
`
                    );

                    selectedSnap = null;
                    await loadSnapshotsForSelectedVol();
                    return;
                }

                if (stStatus === "failed") {
                    throw new Error(`Restore job failed (systemd failed) job=${jobId}`);
                }


                // queued / running / exited / unknown
                status.textContent = `Restoring… (job ${jobId}) status=${stStatus}`;
                await new Promise(r => setTimeout(r, pollEveryMs));
            }

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
    refreshBtn?.addEventListener("click", () => loadAll());

    loadAll();
})();
