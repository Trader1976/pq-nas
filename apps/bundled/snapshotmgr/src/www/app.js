(() => {
    "use strict";
    const el = (id) => document.getElementById(id);

    try {
        if (window.self !== window.top) document.body.classList.add("embedded");
    } catch (_) {
        document.body.classList.add("embedded");
    }

    const appVersionEl = el("appVersion");

    async function getAppVersion() {
        const m = location.pathname.match(/^\/apps\/([^/]+)\/([^/]+)\//);
        if (m && m[2]) return decodeURIComponent(m[2]);

        for (const url of ["../manifest.json", "./manifest.json"]) {
            try {
                const r = await fetch(url, {
                    cache: "no-store",
                    headers: { "Accept": "application/json" }
                });
                if (!r.ok) continue;
                const j = await r.json().catch(() => ({}));
                const ver = j && typeof j.version === "string" ? j.version.trim() : "";
                if (ver) return ver;
            } catch (_) {}
        }

        return "";
    }

    (async () => {
        if (!appVersionEl) return;

        const ver = await getAppVersion();
        if (!ver) {
            appVersionEl.hidden = true;
            return;
        }

        appVersionEl.textContent = `v${ver}`;
        appVersionEl.title = `Snapshot Manager ${ver}`;
        appVersionEl.hidden = false;
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
    const snapNowBtn = el("snapNowBtn");

    let volumes = [];
    let selectedVol = null;   // {name, source_subvolume, snap_root, enabled}
    let snapshots = [];
    let selectedSnap = null;  // {id, path, created_utc, readonly}
    let lastSnapListMeta = null; // { snap_root, volume, count }

    function tr(key, params, fallback) {
        try {
            const api = window.PQNAS_I18N;
            if (api && typeof api.t === "function") {
                return api.t(key, params || null, fallback);
            }
        } catch (_) {}

        let out = String(fallback || key || "");
        const p = params || {};
        for (const name of Object.keys(p)) {
            out = out.split(`{${name}}`).join(String(p[name]));
        }
        return out;
    }

    function snapshotText(text) {
        const s = String(text || "");
        const map = {
            "ready": ["snapshotmgr.badge.ready", "ready"],
            "loading…": ["snapshotmgr.badge.loading", "loading…"],
            "disabled": ["snapshotmgr.badge.disabled", "disabled"],
            "working…": ["snapshotmgr.badge.working", "working…"],
            "done": ["snapshotmgr.badge.done", "done"],
            "error": ["snapshotmgr.badge.error", "error"],
            "restoring…": ["snapshotmgr.badge.restoring", "restoring…"]
        };
        const hit = map[s];
        return hit ? tr(hit[0], null, hit[1]) : s;
    }

    // ---- badge lock (prevents late errors from overwriting badge) ----
    let badgeLockUntil = 0;
    function setBadge(kind, text) {
        const now = Date.now();
        if (now < badgeLockUntil && kind === "err") {
            // Ignore late “err” updates during lock
            return;
        }
        badge.className = `badge ${kind}`;
        badge.textContent = snapshotText(text);
    }
    function lockBadge(ms) {
        badgeLockUntil = Date.now() + Math.max(0, ms || 0);
    }

    // ---- fetch helpers (improved error surface for 502 / downtime) ----

    async function parseJsonBestEffort(r) {
        try { return await r.json(); } catch (_) { return {}; }
    }

    function errorFromResponse(r, j) {
        const msg = (j && (j.message || j.error)) ? (j.message || j.error) : "";
        return new Error(msg || `HTTP ${r.status}`);
    }

    async function apiGet(path) {
        let r;
        try {
            r = await fetch(path, {
                method: "GET",
                credentials: "include",
                cache: "no-store",
                headers: { "Accept": "application/json" }
            });
        } catch (e) {
            throw new Error("network_error");
        }

        const j = await parseJsonBestEffort(r);
        if (!r.ok || (j && j.ok === false)) throw errorFromResponse(r, j);
        return j;
    }

    async function apiPost(path, body) {
        let r;
        try {
            r = await fetch(path, {
                method: "POST",
                credentials: "include",
                cache: "no-store",
                headers: { "Content-Type": "application/json", "Accept": "application/json" },
                body: JSON.stringify(body || {})
            });
        } catch (e) {
            throw new Error("network_error");
        }

        const j = await parseJsonBestEffort(r);
        if (!r.ok || (j && j.ok === false)) throw errorFromResponse(r, j);
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
        modalTitle.textContent = title || tr("snapshotmgr.details", null, "Details");
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

    // Small helper for “progress modal” updates
    function isModalOpen() {
        return !!(modalOverlay && modalOverlay.style.display !== "none" && modalOverlay.getAttribute("aria-hidden") !== "true");
    }

    function setModalHtml(title, html) {
        if (!isModalOpen()) return;
        if (modalTitle) modalTitle.textContent = title || (modalTitle.textContent || tr("snapshotmgr.details", null, "Details"));
        if (modalBody) modalBody.innerHTML = html || "";
    }

    modalCloseBtn?.addEventListener("click", closeModal);
    modalOverlay?.addEventListener("click", (e) => {
        if (e.target === modalOverlay) closeModal();
    });
    window.addEventListener("keydown", (e) => {
        if (e.key === "Escape") closeModal();
    });

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

    function escapeHtml(s) {
        return String(s)
            .replaceAll("&", "&amp;")
            .replaceAll("<", "&lt;")
            .replaceAll(">", "&gt;")
            .replaceAll('"', "&quot;")
            .replaceAll("'", "&#39;");
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
        const volEnabled = !!(selectedVol && selectedVol.enabled);
        const hasSnap = !!selectedSnap;
        const isSub = !!(selectedSnap && selectedSnap.is_btrfs_subvolume === true);
        const probe = String((selectedSnap && selectedSnap.probe) || "ok");

        detailsBtn.disabled = !hasSnap;
        snapNowBtn.disabled = !(hasVol && volEnabled);
        restoreBtn.disabled = !(hasVol && hasSnap && isSub && probe !== "no_privs");
    }

    function renderVolumes() {
        clearChildren(volList);
        volHint.textContent = volumes.length ? `${volumes.length}` : "";

        for (const v of volumes) {
            const isSel = selectedVol && selectedVol.name === v.name;
            const d = row(
                v.name,
                v.enabled ? tr("snapshotmgr.enabled", null, "enabled") : tr("snapshotmgr.disabled", null, "disabled"),
                `${v.source_subvolume}  |  ${v.snap_root}`,
                isSel
            );
            d.addEventListener("click", () => {
                selectedVol = v;
                selectedSnap = null;
                renderVolumes();

                if (v.enabled === false) {
                    status.textContent = tr("snapshotmgr.status.volume_disabled_loading", { volume: v.name }, "Volume {volume} is disabled for new snapshots. Loading existing snapshots…");
                }

                loadSnapshotsForSelectedVol().catch(() => {});
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
            if (isLatest) right = tr("snapshotmgr.latest", null, "latest");
            else if (probe === "no_privs") right = "⚠";
            else if (!isSub) right = tr("snapshotmgr.junk", null, "junk");
            else right = (s.readonly ? tr("snapshotmgr.readonly_short", null, "ro") : tr("snapshotmgr.readwrite_short", null, "rw"));

            const sub = s.created_utc || s.path || "";

            const d = row(s.id, right, sub, isSel);
            if (probe === "no_privs") d.classList.add("noPrivs");
            if (!isSub) d.classList.add("notSubvol");

            // tooltip on right-side label
            const rightEl = d.querySelector(".top .mono");
            if (rightEl) {
                if (probe === "no_privs") {
                    const tip = escapeHtml(tr("snapshotmgr.tooltip.no_sudo", null, "No sudo privileges to verify btrfs subvolume (sudo -n failed)"));
                    rightEl.innerHTML = `<span class="pillWarn" title="${tip}">⚠</span>`;
                } else if (!isSub) {
                    rightEl.title = tr("snapshotmgr.tooltip.junk", null, "This folder is not a btrfs snapshot subvolume (junk under snap_root)");
                } else if (isLatest) {
                    rightEl.title = tr("snapshotmgr.tooltip.latest", null, "Newest snapshot (server sorted newest-first)");
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
                    status.textContent = tr("snapshotmgr.status.selected_no_sudo", { id: s.id }, "Selected: {id} (cannot verify btrfs subvolume; sudo rule missing)");
                } else if (!isSub) {
                    status.textContent = tr("snapshotmgr.status.selected_not_subvolume", { id: s.id }, "Selected: {id} (NOT a btrfs snapshot subvolume)");
                } else {
                    status.textContent = tr("snapshotmgr.status.selected_snapshot", { id: s.id }, "Selected snapshot: {id}");
                }
            });

            snapList.appendChild(d);
        }

        if (!snapshots.length) {
            const d = row(tr("snapshotmgr.no_snapshots_found", null, "(no snapshots found)"), "", tr("snapshotmgr.no_snapshots_hint", null, "Check snap_root path and snapshot runner output."), false);
            d.style.cursor = "default";
            snapList.appendChild(d);
        }
    }

    async function loadVolumes() {
        setBadge("warn", "loading…");
        status.textContent = tr("snapshotmgr.status.loading_volumes", null, "Loading volumes…");

        const j = await apiGet("/api/v4/snapshots/volumes");

        window.__pqnasRuntimeUser =
            (j && typeof j.runtime_user === "string" && j.runtime_user.trim())
                ? j.runtime_user.trim()
                : "";

        volumes = Array.isArray(j.volumes) ? j.volumes : [];
        volumes.sort((a, b) => String(a.name).localeCompare(String(b.name)));

        if (!selectedVol && volumes.length) selectedVol = volumes[0];

        renderVolumes();
        setBadge("ok", "ready");
        status.textContent = tr("snapshotmgr.status.volumes_loaded", null, "Volumes loaded.");
    }

    async function loadSnapshotsForSelectedVol() {
        updateButtons();

        if (!selectedVol) {
            snapshots = [];
            renderSnapshots();
            return;
        }

        setBadge("warn", "loading…");
        status.textContent = tr("snapshotmgr.status.loading_snapshots_for_volume", { volume: selectedVol.name }, "Loading snapshots for {volume}…");

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
        const volEnabled = !!(selectedVol && selectedVol.enabled);

        if (!volEnabled) {
            showBanner(tr("snapshotmgr.banner.snapshots_disabled_html", {
                volume: `<span class="mono">${escapeHtml(selectedVol.name)}</span>`
            }, `⚠ Snapshots are <b>disabled</b> for volume <span class="mono">${escapeHtml(selectedVol.name)}</span> in Admin Settings. Existing snapshots can still be viewed, but <b>Snapshot now</b> is unavailable.`));
        } else if (noPrivsCount > 0) {
            showBanner(tr("snapshotmgr.banner.sudo_required_html", {
                count: noPrivsCount,
                link: `<a href="#" id="sudoHelpLink">${escapeHtml(tr("snapshotmgr.show_sudo_setup", null, "Show sudo setup"))}</a>`
            }, `⚠ Snapshot verification needs sudo privileges on this host. ${noPrivsCount} item(s) could not be verified. <a href="#" id="sudoHelpLink">Show sudo setup</a>`));
            setTimeout(() => {
                const a = document.getElementById("sudoHelpLink");
                a?.addEventListener("click", (ev) => {
                    ev.preventDefault();
                    openModal(tr("snapshotmgr.sudo_setup", null, "Sudo setup"), sudoSetupHtml());
                });
            }, 0);
        } else if (junkCount > 0) {
            showBanner(tr("snapshotmgr.banner.junk_items", { count: junkCount }, "Note: {count} item(s) under snap_root are not btrfs snapshot subvolumes (junk folders)."));
        } else {
            showBanner("");
        }

        renderSnapshots();
        if (!selectedSnap && snapshots.length) {
            selectedSnap = snapshots[0];
            renderSnapshots();
        }

        setBadge("ok", "ready");
        if (selectedVol && selectedVol.enabled === false) {
            status.textContent = tr("snapshotmgr.status.snapshots_loaded_disabled", { volume: selectedVol.name }, "Snapshots loaded for {volume}. Snapshots are disabled for this volume, so manual create is unavailable.");
        } else {
            status.textContent = tr("snapshotmgr.status.snapshots_loaded", { volume: selectedVol.name }, "Snapshots loaded for {volume}.");
        }
        updateButtons();
    }

    async function showDetails() {
        if (!selectedVol || !selectedSnap) return;
        try {
            setBadge("warn", "loading…");
            status.textContent = tr("snapshotmgr.status.loading_details", null, "Loading details…");

            const qs = new URLSearchParams({ volume: selectedVol.name, id: selectedSnap.id });
            const j = await apiGet(`/api/v4/snapshots/info?${qs.toString()}`);

            const raw = JSON.stringify(j, null, 2);

            const needsSudo =
                (j && typeof j.btrfs_show === "string" && j.btrfs_show.toLowerCase().includes("operation not permitted")) ||
                (selectedSnap && String(selectedSnap.probe || "") === "no_privs");

            if (needsSudo) {
                openModal(
                    tr("snapshotmgr.details.title_for_id", { id: selectedSnap.id }, `Snapshot details: ${selectedSnap.id}`),
                    `
      <div class="modalGrid">
        <div class="modalPanel">
          <h3><span class="warnIcon">⚠</span> ${escapeHtml(tr("snapshotmgr.details.sudo_required_title", null, "Details require sudo privileges"))}</h3>
          <div class="modalNote">
            ${tr("snapshotmgr.details.sudo_required_body_html", null, "Snapshot Manager calls <span class=\"mono\">sudo -n btrfs subvolume show ...</span>. If sudo prompts for a password, probing becomes <b>no-privs</b> and restore stays disabled.")}
          </div>

          <div class="modalNote">
            <a href="#" id="sudoInlineLink">${escapeHtml(tr("snapshotmgr.details.show_sudo_setup_instructions", null, "Show sudo setup instructions"))}</a>
          </div>

          <div id="sudoBlock" style="display:none;">
            ${sudoSetupHtml()}
          </div>
        </div>

        <div class="modalPanel">
          <h3>${escapeHtml(tr("snapshotmgr.raw_json", null, "Raw JSON"))}</h3>
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
                    tr("snapshotmgr.details.title_for_id", { id: selectedSnap.id }, `Snapshot details: ${selectedSnap.id}`),
                    `<div class="modalGrid">
       <div class="modalPanel">
         <h3>${escapeHtml(tr("snapshotmgr.raw_json", null, "Raw JSON"))}</h3>
         <pre class="mono">${escapeHtml(raw)}</pre>
       </div>
     </div>`
                );
            }

            setBadge("ok", "ready");
            status.textContent = tr("snapshotmgr.ready", null, "Ready.");
        } catch (e) {
            setBadge("err", "error");
            status.textContent = tr("snapshotmgr.status.details_failed", { error: String(e && e.message ? e.message : e) }, "Details failed: {error}");
        }
    }


    function openSnapshotConfirmModal(opts = {}) {
        return new Promise((resolve) => {
            const options = opts || {};

            const modal = document.createElement("div");
            modal.className = "modalOverlay snapshotConfirmOverlay";
            modal.style.display = "flex";
            modal.setAttribute("role", "dialog");
            modal.setAttribute("aria-modal", "true");

            const card = document.createElement("div");
            card.className = "modalCard";
            card.style.width = "min(680px, calc(100vw - 24px))";

            const head = document.createElement("div");
            head.className = "modalHead";

            const headText = document.createElement("div");

            const title = document.createElement("div");
            title.className = "modalTitle";
            title.textContent = options.title || "Confirm action";

            const sub = document.createElement("div");
            sub.className = "modalSub";
            sub.textContent = options.subtitle || "";

            headText.appendChild(title);
            if (sub.textContent) headText.appendChild(sub);
            head.appendChild(headText);

            const body = document.createElement("div");
            body.className = "modalBody";
            body.style.gridTemplateColumns = "140px 1fr";

            const rows = Array.isArray(options.rows) ? options.rows : [];
            for (const row of rows) {
                const k = document.createElement("div");
                k.className = "k";
                k.textContent = String(row.label || "");

                const v = document.createElement("div");
                v.className = row.mono ? "v mono" : "v";
                v.textContent = String(row.value || "");

                body.appendChild(k);
                body.appendChild(v);
            }

            if (options.warning) {
                const warn = document.createElement("div");
                warn.className = "v";
                warn.style.gridColumn = "1 / -1";
                warn.style.padding = "10px 12px";
                warn.style.border = "1px solid rgba(var(--fail-rgb),0.42)";
                warn.style.borderRadius = "14px";
                warn.style.background = "rgba(var(--fail-rgb),0.12)";
                warn.style.fontWeight = "900";
                warn.textContent = String(options.warning || "");
                body.appendChild(warn);
            }

            if (options.note) {
                const note = document.createElement("div");
                note.className = "v";
                note.style.gridColumn = "1 / -1";
                note.style.opacity = "0.9";
                note.textContent = String(options.note || "");
                body.appendChild(note);
            }

            const foot = document.createElement("div");
            foot.className = "modalFoot";

            const spacer = document.createElement("div");
            spacer.style.flex = "1 1 auto";

            const cancelBtn = document.createElement("button");
            cancelBtn.type = "button";
            cancelBtn.className = "btn secondary";
            cancelBtn.textContent = options.cancelText || "Cancel";

            const okBtn = document.createElement("button");
            okBtn.type = "button";
            okBtn.className = "btn";
            okBtn.textContent = options.confirmText || "OK";

            if (options.danger) {
                okBtn.style.borderColor = "rgba(var(--fail-rgb),0.45)";
                okBtn.style.background = "rgba(var(--fail-rgb),0.14)";
                okBtn.style.color = "var(--fg)";
            }

            foot.appendChild(spacer);
            foot.appendChild(cancelBtn);
            foot.appendChild(okBtn);

            card.appendChild(head);
            card.appendChild(body);
            card.appendChild(foot);
            modal.appendChild(card);
            document.body.appendChild(modal);

            const close = (value) => {
                document.removeEventListener("keydown", onKey, true);
                modal.remove();
                resolve(!!value);
            };

            const onKey = (ev) => {
                if (ev.key === "Escape") {
                    ev.preventDefault();
                    ev.stopPropagation();
                    close(false);
                    return;
                }

                if (ev.key === "Enter") {
                    ev.preventDefault();
                    ev.stopPropagation();
                    close(true);
                }
            };

            document.addEventListener("keydown", onKey, true);
            modal.addEventListener("click", (ev) => {
                if (ev.target === modal) close(false);
            });

            cancelBtn.addEventListener("click", () => close(false));
            okBtn.addEventListener("click", () => close(true));

            window.setTimeout(() => {
                if (options.danger) cancelBtn.focus();
                else okBtn.focus();
            }, 0);
        });
    }

    function openSnapshotTypedConfirmModal(opts = {}) {
        return new Promise((resolve) => {
            const options = opts || {};
            const expected = String(options.expected || "");

            const modal = document.createElement("div");
            modal.className = "modalOverlay snapshotConfirmOverlay";
            modal.style.display = "flex";
            modal.setAttribute("role", "dialog");
            modal.setAttribute("aria-modal", "true");

            const card = document.createElement("div");
            card.className = "modalCard";
            card.style.width = "min(720px, calc(100vw - 24px))";

            const head = document.createElement("div");
            head.className = "modalHead";

            const headText = document.createElement("div");

            const title = document.createElement("div");
            title.className = "modalTitle";
            title.textContent = options.title || "Confirm restore";

            const sub = document.createElement("div");
            sub.className = "modalSub";
            sub.textContent = options.subtitle || "";

            headText.appendChild(title);
            if (sub.textContent) headText.appendChild(sub);
            head.appendChild(headText);

            const body = document.createElement("div");
            body.className = "modalBody";
            body.style.gridTemplateColumns = "1fr";

            const warning = document.createElement("div");
            warning.className = "v";
            warning.style.padding = "10px 12px";
            warning.style.border = "1px solid rgba(var(--fail-rgb),0.42)";
            warning.style.borderRadius = "14px";
            warning.style.background = "rgba(var(--fail-rgb),0.12)";
            warning.style.fontWeight = "900";
            warning.textContent = options.warning || "This action requires typed confirmation.";
            body.appendChild(warning);

            const phrase = document.createElement("div");
            phrase.className = "v mono";
            phrase.style.padding = "10px 12px";
            phrase.style.border = "1px solid var(--border2)";
            phrase.style.borderRadius = "14px";
            phrase.style.background = "rgba(0,0,0,0.18)";
            phrase.textContent = expected;
            body.appendChild(phrase);

            const label = document.createElement("label");
            label.className = "k";
            label.textContent = "Type the confirmation phrase exactly:";
            body.appendChild(label);

            const input = document.createElement("input");
            input.type = "text";
            input.autocomplete = "off";
            input.spellcheck = false;
            input.style.width = "100%";
            input.style.padding = "10px 12px";
            input.style.borderRadius = "12px";
            input.style.border = "1px solid var(--border2)";
            input.style.background = "rgba(0,0,0,0.22)";
            input.style.color = "var(--fg)";
            input.style.font = "inherit";
            input.style.fontFamily = "var(--mono)";
            body.appendChild(input);

            const err = document.createElement("div");
            err.className = "v";
            err.style.display = "none";
            err.style.padding = "8px 10px";
            err.style.border = "1px solid rgba(var(--fail-rgb),0.35)";
            err.style.borderRadius = "12px";
            err.style.background = "rgba(var(--fail-rgb),0.10)";
            err.style.fontWeight = "850";
            body.appendChild(err);

            const foot = document.createElement("div");
            foot.className = "modalFoot";

            const hint = document.createElement("div");
            hint.className = "v";
            hint.style.opacity = "0.75";
            hint.style.fontSize = "12px";
            hint.textContent = options.note || "";

            const spacer = document.createElement("div");
            spacer.style.flex = "1 1 auto";

            const cancelBtn = document.createElement("button");
            cancelBtn.type = "button";
            cancelBtn.className = "btn secondary";
            cancelBtn.textContent = options.cancelText || "Cancel";

            const okBtn = document.createElement("button");
            okBtn.type = "button";
            okBtn.className = "btn";
            okBtn.textContent = options.confirmText || "Continue";
            okBtn.style.borderColor = "rgba(var(--fail-rgb),0.45)";
            okBtn.style.background = "rgba(var(--fail-rgb),0.14)";
            okBtn.style.color = "var(--fg)";

            foot.appendChild(hint);
            foot.appendChild(spacer);
            foot.appendChild(cancelBtn);
            foot.appendChild(okBtn);

            card.appendChild(head);
            card.appendChild(body);
            card.appendChild(foot);
            modal.appendChild(card);
            document.body.appendChild(modal);

            const showError = (text) => {
                err.textContent = text || "";
                err.style.display = text ? "block" : "none";
            };

            const close = (value) => {
                document.removeEventListener("keydown", onKey, true);
                modal.remove();
                resolve(!!value);
            };

            const submit = () => {
                if (String(input.value || "") !== expected) {
                    showError("Confirmation phrase does not match.");
                    input.focus();
                    input.select();
                    return;
                }
                close(true);
            };

            const onKey = (ev) => {
                if (ev.key === "Escape") {
                    ev.preventDefault();
                    ev.stopPropagation();
                    close(false);
                    return;
                }

                if (ev.key === "Enter") {
                    ev.preventDefault();
                    ev.stopPropagation();
                    submit();
                }
            };

            document.addEventListener("keydown", onKey, true);
            modal.addEventListener("click", (ev) => {
                if (ev.target === modal) close(false);
            });

            cancelBtn.addEventListener("click", () => close(false));
            okBtn.addEventListener("click", submit);

            window.setTimeout(() => {
                input.focus();
            }, 0);
        });
    }

    // ---- Restore ----

    function restoreProgressModalHtml(jobId, phase, extra) {
        const phaseText = phase || "starting";
        const extraText = extra ? `<div class="modalNote" style="margin-top:8px;">${extra}</div>` : "";
        return `
<div class="modalGrid">
  <div class="modalPanel">
    <h3>Restore in progress</h3>
    <div class="modalNote">
      PQ-NAS stops briefly during restore. Behind Cloudflare Tunnel you may see temporary <b>502</b>.
    </div>
    <div class="modalNote mono">job_id=${escapeHtml(jobId || "(pending)")}</div>
    <div class="modalNote">Status: <b>${escapeHtml(phaseText)}</b></div>
    ${extraText}
  </div>
  <div class="modalPanel">
    <h3>What’s happening</h3>
    <pre class="mono" style="white-space:pre-wrap; overflow:auto; max-height:260px;">${escapeHtml(
            [
                "1) Prepare restore plan",
                "2) Start systemd restore job",
                "3) Stop pqnas.service",
                "4) Swap live subvolume from snapshot",
                "5) Start pqnas.service",
                "6) Job writes /run/pqnas/restore/<job>.result.json"
            ].join("\n")
        )}</pre>
  </div>
</div>`;
    }

    function isRetryableDuringRestore(err) {
        const msg = String(err && err.message ? err.message : err || "");
        if (msg === "network_error") return true;
        if (msg.includes("HTTP 502")) return true;
        if (msg.includes("HTTP 503")) return true;
        if (msg.includes("HTTP 504")) return true;
        if (msg.includes("HTTP 520")) return true;
        if (msg.includes("HTTP 521")) return true;
        if (msg.includes("HTTP 522")) return true;
        if (msg.includes("HTTP 523")) return true;
        if (msg.includes("HTTP 524")) return true;
        if (msg.includes("Failed to fetch")) return true;
        if (msg.includes("NetworkError")) return true;
        if (msg.includes("Load failed")) return true;
        return false;
    }

    function openSnapshotNameModal(opts = {}) {
        return new Promise((resolve) => {
            const options = opts || {};
            const modal = document.createElement("div");
            modal.className = "modalOverlay snapshotNameOverlay";
            modal.style.display = "flex";
            modal.setAttribute("role", "dialog");
            modal.setAttribute("aria-modal", "true");

            const card = document.createElement("div");
            card.className = "modalCard";
            card.style.width = "min(560px, calc(100vw - 24px))";

            const head = document.createElement("div");
            head.className = "modalHead";

            const headText = document.createElement("div");

            const title = document.createElement("div");
            title.className = "modalTitle";
            title.textContent = options.title || tr("snapshotmgr.snapshot_now.title", null, "Snapshot now");

            const sub = document.createElement("div");
            sub.className = "modalSub";
            sub.textContent = options.subtitle || "";

            headText.appendChild(title);
            if (sub.textContent) headText.appendChild(sub);
            head.appendChild(headText);

            const body = document.createElement("div");
            body.className = "modalBody";
            body.style.gridTemplateColumns = "1fr";

            const note = document.createElement("div");
            note.className = "v";
            note.textContent = options.note || tr("snapshotmgr.snapshot_now.name_help", null, "Optional name. Leave empty for automatic snapshot ID.");
            body.appendChild(note);

            const input = document.createElement("input");
            input.type = "text";
            input.autocomplete = "off";
            input.spellcheck = false;
            input.maxLength = 160;
            input.value = String(options.defaultValue || "");
            input.placeholder = tr("snapshotmgr.snapshot_now.placeholder", null, "Snapshot name");
            input.style.width = "100%";
            input.style.padding = "10px 12px";
            input.style.borderRadius = "12px";
            input.style.border = "1px solid var(--border2)";
            input.style.background = "rgba(0,0,0,0.22)";
            input.style.color = "var(--fg)";
            input.style.font = "inherit";
            input.style.fontFamily = "var(--mono)";
            body.appendChild(input);

            const foot = document.createElement("div");
            foot.className = "modalFoot";

            const spacer = document.createElement("div");
            spacer.style.flex = "1 1 auto";

            const cancelBtn = document.createElement("button");
            cancelBtn.type = "button";
            cancelBtn.className = "btn secondary";
            cancelBtn.textContent = options.cancelText || tr("common.cancel", null, "Cancel");

            const okBtn = document.createElement("button");
            okBtn.type = "button";
            okBtn.className = "btn";
            okBtn.textContent = options.confirmText || tr("snapshotmgr.snapshot_now.create", null, "Create snapshot");

            foot.appendChild(spacer);
            foot.appendChild(cancelBtn);
            foot.appendChild(okBtn);

            card.appendChild(head);
            card.appendChild(body);
            card.appendChild(foot);
            modal.appendChild(card);
            document.body.appendChild(modal);

            const close = (value) => {
                document.removeEventListener("keydown", onKey, true);
                modal.remove();
                resolve(value);
            };

            const submit = () => {
                close(String(input.value || "").trim());
            };

            const onKey = (ev) => {
                if (ev.key === "Escape") {
                    ev.preventDefault();
                    ev.stopPropagation();
                    close(null);
                    return;
                }

                if (ev.key === "Enter") {
                    ev.preventDefault();
                    ev.stopPropagation();
                    submit();
                }
            };

            document.addEventListener("keydown", onKey, true);
            modal.addEventListener("click", (ev) => {
                if (ev.target === modal) close(null);
            });

            cancelBtn.addEventListener("click", () => close(null));
            okBtn.addEventListener("click", submit);

            window.setTimeout(() => {
                input.focus();
                input.select();
            }, 0);
        });
    }

    async function doSnapshotNow() {
        if (!selectedVol) return;
        if (selectedVol.enabled === false) {
            setBadge("warn", "disabled");
            status.textContent = tr("snapshotmgr.status.snapshots_disabled_for_volume", { volume: selectedVol.name }, "Snapshots are disabled for {volume} in Admin Settings.");
            return;
        }

        const vol = selectedVol.name;

        // Optional name; empty means server auto-generates ID
        const suggested = `MANUAL_${new Date().toISOString().replaceAll(":", "-")}`;
        const name = await openSnapshotNameModal({
            title: tr("snapshotmgr.snapshot_now.title", null, "Snapshot now"),
            subtitle: tr("snapshotmgr.snapshot_now.volume", { volume: vol }, "Volume: {volume}"),
            note: tr("snapshotmgr.snapshot_now.name_help", null, "Optional name. Leave empty for automatic snapshot ID."),
            defaultValue: suggested,
            confirmText: tr("snapshotmgr.snapshot_now.create", null, "Create snapshot"),
            cancelText: tr("common.cancel", null, "Cancel")
        });
        if (name === null) return; // user cancelled

        setBadge("warn", "working…");
        status.textContent = tr("snapshotmgr.status.creating_snapshot", { volume: vol }, "Creating snapshot for {volume}…");

        try {
            // TODO: replace endpoint + body once we confirm your actual API
            const res = await apiPost("/api/v4/snapshots/create", {
                volume: vol,
                id: String(name || "").trim() || undefined,
                kind: "manual"
            });

            // Expect server to return snapshot id in one of these fields
            const newId =
                (res && typeof res.id === "string" && res.id) ? res.id :
                    (res && typeof res.snapshot_id === "string" && res.snapshot_id) ? res.snapshot_id :
                        "";

            setBadge("ok", "done");
            status.textContent = newId
                ? tr("snapshotmgr.status.snapshot_created_id", { id: newId }, "✅ Snapshot created: {id}")
                : tr("snapshotmgr.status.snapshot_created", null, "✅ Snapshot created.");

            // Refresh list and select new snapshot if we know its id
            await loadSnapshotsForSelectedVol();
            if (newId) {
                const found = snapshots.find(s => s.id === newId);
                if (found) {
                    selectedSnap = found;
                    renderSnapshots();
                    updateButtons();
                }
            }

            setBadge("ok", "ready");
            status.textContent = tr("snapshotmgr.ready", null, "Ready.");
        } catch (e) {
            const msg = String(e && e.message ? e.message : e);
            if (msg.toLowerCase().includes("disabled")) {
                setBadge("warn", "disabled");
                status.textContent = tr("snapshotmgr.status.snapshots_disabled_for_volume", { volume: vol }, "Snapshots are disabled for {volume} in Admin Settings.");
            } else {
                setBadge("err", "error");
                status.textContent = tr("snapshotmgr.status.snapshot_now_failed", { error: msg }, "Snapshot now failed: {error}");
            }
        } finally {
            updateButtons();
        }
    }

    async function doRestore() {
        if (!selectedVol || !selectedSnap) return;

        const vol = selectedVol.name;
        const id = selectedSnap.id;
        const isSub = (selectedSnap && selectedSnap.is_btrfs_subvolume === true);
        const probe = String((selectedSnap && selectedSnap.probe) || "ok");
        if (!isSub || probe === "no_privs") {
            status.textContent = tr("snapshotmgr.restore.disabled_not_verified", null, "Restore disabled: snapshot not verified as a btrfs subvolume (or sudo missing).");
            return;
        }

        const phrase = `RESTORE ${vol} ${id}`;

        const ok1 = await openSnapshotConfirmModal({
            title: tr("snapshotmgr.restore.confirm1.title", null, "Restore snapshot?"),
            subtitle: tr("snapshotmgr.restore.confirm1.subtitle", null, "This will replace the live volume content."),
            rows: [
                { label: tr("snapshotmgr.volume", null, "Volume"), value: vol, mono: true },
                { label: tr("snapshotmgr.snapshot", null, "Snapshot"), value: id, mono: true },
            ],
            warning: tr("snapshotmgr.restore.confirm1.warning", null, "This will REPLACE the live volume content. Downtime required."),
            note: tr("snapshotmgr.restore.confirm1.note", null, "A restore job will stop and restart PQ-NAS while the volume is swapped."),
            confirmText: tr("snapshotmgr.restore.continue", null, "Continue"),
            cancelText: tr("common.cancel", null, "Cancel"),
            danger: true,
        });
        if (!ok1) return;

        const typedOk = await openSnapshotTypedConfirmModal({
            title: tr("snapshotmgr.restore.confirm2.title", null, "Confirm restore"),
            subtitle: tr("snapshotmgr.restore.confirm2.subtitle", null, "Typed confirmation is required before restore can continue."),
            expected: phrase,
            warning: tr("snapshotmgr.restore.confirm2.warning", { id, volume: vol }, `You are restoring snapshot ${id} into live volume ${vol}.`),
            note: tr("snapshotmgr.restore.confirm2.note", null, "This prevents accidental restores."),
            confirmText: tr("snapshotmgr.restore.continue_restore", null, "Continue restore"),
            cancelText: tr("common.cancel", null, "Cancel"),
        });
        if (!typedOk) {
            status.textContent = tr("snapshotmgr.restore.canceled", null, "Restore canceled.");
            return;
        }

        setBadge("warn", "working…");
        status.textContent = tr("snapshotmgr.restore.preparing", null, "Preparing restore…");

        try {
            const prep = await apiPost("/api/v4/snapshots/restore/prepare", {
                volume: vol,
                id,
                mode: "swap",
                force_stop: true
            });

            const planText = JSON.stringify(prep.plan || {}, null, 2);
            const ok2 = await openSnapshotConfirmModal({
                title: tr("snapshotmgr.restore.confirm3.title", null, "Proceed with restore plan?"),
                subtitle: tr("snapshotmgr.restore.confirm3.subtitle", null, "Server has prepared the restore plan."),
                rows: [
                    { label: tr("snapshotmgr.volume", null, "Volume"), value: vol, mono: true },
                    { label: tr("snapshotmgr.snapshot", null, "Snapshot"), value: id, mono: true },
                    { label: tr("snapshotmgr.plan", null, "Plan"), value: planText, mono: true },
                ],
                warning: tr("snapshotmgr.restore.confirm3.warning", null, "Proceeding starts the restore job now."),
                note: tr("snapshotmgr.restore.confirm3.note", null, "PQ-NAS may be temporarily unreachable during restore."),
                confirmText: tr("snapshotmgr.restore.start", null, "Start restore"),
                cancelText: tr("common.cancel", null, "Cancel"),
                danger: true,
            });
            if (!ok2) {
                setBadge("ok", "ready");
                status.textContent = tr("snapshotmgr.restore.canceled", null, "Restore canceled.");
                return;
            }

            setBadge("warn", "working…");
            status.textContent = tr("snapshotmgr.restore.starting_job", null, "Starting restore job…");

            const done = await apiPost("/api/v4/snapshots/restore/confirm", {
                confirm_id: prep.confirm_id,
                confirm_text: phrase
            });

            const jobId = String((done && done.job_id) || "");
            if (!jobId) throw new Error(tr("snapshotmgr.restore.no_job_id", null, "Restore started but server did not return job_id"));

            openModal(tr("snapshotmgr.restore.title", null, "Restore"), restoreProgressModalHtml(jobId, tr("snapshotmgr.restore.queued", null, "queued"), ""));

            setBadge("warn", "restoring…");
            status.textContent = tr("snapshotmgr.restore.restoring_job", { job_id: jobId }, `Restoring… (job ${jobId})`);

            const pollEveryMs = 1200;
            const timeoutMs = 10 * 60 * 1000;
            const graceMs = 90 * 1000;
            const t0 = Date.now();
            const tGraceStart = Date.now();

            while (true) {
                if (Date.now() - t0 > timeoutMs) {
                    throw new Error(tr("snapshotmgr.restore.timeout", { job_id: jobId }, `Restore timed out waiting for result (job ${jobId})`));
                }

                let st;
                try {
                    st = await apiGet(`/api/v4/snapshots/restore/status?job_id=${encodeURIComponent(jobId)}`);
                } catch (e) {
                    const inGrace = (Date.now() - tGraceStart) < graceMs;
                    if (inGrace && isRetryableDuringRestore(e)) {
                        status.textContent = tr("snapshotmgr.restore.restarting_server_job", { job_id: jobId }, `Restoring… (job ${jobId}) restarting server…`);
                        setModalHtml(tr("snapshotmgr.restore.title", null, "Restore"), restoreProgressModalHtml(jobId, tr("snapshotmgr.restore.restarting_server", null, "restarting server…"), tr("snapshotmgr.restore.waiting_online", null, "Waiting for PQ-NAS to come back online (temporary 502 is expected).")));
                        // IMPORTANT: do NOT set badge to err on retryable errors during restore
                        setBadge("warn", "restoring…");
                        await new Promise(r => setTimeout(r, pollEveryMs));
                        continue;
                    }
                    throw e;
                }

                const hasWrapped = (st && typeof st.status === "string");
                const stStatus = hasWrapped
                    ? String(st.status || "unknown")
                    : (st && typeof st.step === "string") ? "done" : "unknown";

                const r = hasWrapped ? (st.result || null) : st;

                if (stStatus !== "done") {
                    setModalHtml("Restore", restoreProgressModalHtml(jobId, stStatus, ""));
                }

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

                    // Prevent late “err” from loadAll()/anything while we refresh UI
                    lockBadge(6000);

                    selectedSnap = null;

                    // Refresh snapshots, but NEVER allow refresh failure to flip badge to error
                    try {
                        await loadSnapshotsForSelectedVol();
                    } catch (e) {
                        const msg = String(e && e.message ? e.message : e);
                        status.textContent = `Restore completed. (Refresh failed: ${msg})`;
                    }

                    // Always end in ready state if restore ok
                    if (ok) {
                        setBadge("ok", "ready");
                        status.textContent = "Restore completed. Ready.";
                    } else {
                        // For failures keep error
                        setBadge("err", "failed");
                    }

                    updateButtons();
                    return;
                }

                if (stStatus === "failed") {
                    throw new Error(`Restore job failed (systemd failed) job=${jobId}`);
                }

                status.textContent = `Restoring… (job ${jobId}) status=${stStatus}`;
                await new Promise(r => setTimeout(r, pollEveryMs));
            }

        } catch (e) {
            const msg = String(e && e.message ? e.message : e);

            if (isRetryableDuringRestore(e)) {
                // Don’t scare user with a red badge for tunnel hiccups
                setBadge("warn", "waiting…");
                status.textContent = `Temporary connection issue (expected during restore): ${msg}`;
            } else {
                setBadge("err", "error");
                status.textContent = `Restore failed: ${msg}`;
            }
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
            const msg = String(e && e.message ? e.message : e);

            // IMPORTANT: if tunnel/origin is flapping, don’t flip to “error”
            if (isRetryableDuringRestore(e)) {
                setBadge("warn", "waiting…");
                status.textContent = `Waiting for PQ-NAS… (${msg})`;
                return;
            }

            setBadge("err", "error");
            status.textContent = msg;
        }
    }

    detailsBtn?.addEventListener("click", showDetails);
    restoreBtn?.addEventListener("click", doRestore);
    snapNowBtn?.addEventListener("click", doSnapshotNow);
    refreshBtn?.addEventListener("click", () => loadAll());

    loadAll();
})();
