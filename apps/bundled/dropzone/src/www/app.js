(() => {
  "use strict";

  const el = (id) => document.getElementById(id);

  const statusLine = el("statusLine");
  const zonesList = el("zonesList");
  const refreshBtn = el("refreshBtn");
  const createBtn = el("createBtn");

  const createModal = el("createModal");
  const modalCloseBtn = el("modalCloseBtn");
  const cancelCreateBtn = el("cancelCreateBtn");
  const createForm = el("createForm");
  const createResult = el("createResult");
  const submitCreateBtn = el("submitCreateBtn");

  const zoneNameInput = el("zoneNameInput");
  const destInput = el("destInput");
  const expiryInput = el("expiryInput");
  const passwordInput = el("passwordInput");
  const maxFileInput = el("maxFileInput");
  const maxTotalInput = el("maxTotalInput");

  function escapeHtml(s) {
    return String(s == null ? "" : s)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll("\"", "&quot;")
        .replaceAll("'", "&#39;");
  }

  function setStatus(text) {
    if (statusLine) statusLine.textContent = text || "";
  }

  function fmtBytes(n) {
    n = Number(n || 0);
    if (!Number.isFinite(n) || n <= 0) return "No limit";

    const units = ["B", "KiB", "MiB", "GiB", "TiB"];
    let i = 0;

    while (n >= 1024 && i < units.length - 1) {
      n /= 1024;
      i++;
    }

    return `${n.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
  }

  function fmtEpoch(epoch) {
    const n = Number(epoch || 0);
    if (!Number.isFinite(n) || n <= 0) return "Never";

    try {
      return new Date(n * 1000).toLocaleString();
    } catch (_) {
      return String(epoch);
    }
  }

  function setBusy(on) {
    if (refreshBtn) refreshBtn.disabled = !!on;
    if (createBtn) createBtn.disabled = !!on;
  }

  function setCreateBusy(on) {
    if (submitCreateBtn) submitCreateBtn.disabled = !!on;
    if (cancelCreateBtn) cancelCreateBtn.disabled = !!on;
    if (modalCloseBtn) modalCloseBtn.disabled = !!on;
  }

  function renderEmpty(message) {
    if (!zonesList) return;
    zonesList.innerHTML = `<div class="dzEmpty">${escapeHtml(message)}</div>`;
  }

  function openCreateModal() {
    if (!createModal) return;

    if (createForm) createForm.reset();
    if (createResult) {
      createResult.classList.add("hidden");
      createResult.innerHTML = "";
    }

    if (zoneNameInput) zoneNameInput.value = "Drop Zone";
    if (destInput) destInput.value = "Incoming/Drop Zones/Drop Zone";

    createModal.classList.remove("hidden");
    createModal.setAttribute("aria-hidden", "false");

    setTimeout(() => zoneNameInput?.focus(), 0);
  }

  function closeCreateModal() {
    if (!createModal) return;

    createModal.classList.add("hidden");
    createModal.setAttribute("aria-hidden", "true");
  }

  function showCreateResult(kind, html) {
    if (!createResult) return;

    createResult.classList.remove("hidden", "ok", "fail");
    createResult.classList.add(kind === "ok" ? "ok" : "fail");
    createResult.innerHTML = html;
  }

  async function copyText(text) {
    const s = String(text || "");
    if (!s) return false;

    try {
      await navigator.clipboard.writeText(s);
      return true;
    } catch (_) {
      const ta = document.createElement("textarea");
      ta.value = s;
      ta.setAttribute("readonly", "readonly");
      ta.style.position = "fixed";
      ta.style.left = "-9999px";
      document.body.appendChild(ta);
      ta.select();

      let ok = false;
      try {
        ok = document.execCommand("copy");
      } catch (_) {
        ok = false;
      }

      ta.remove();
      return ok;
    }
  }

  async function apiJson(url, opts) {
    const res = await fetch(url, {
      cache: "no-store",
      credentials: "include",
      headers: {
        "Accept": "application/json",
        ...(opts && opts.headers ? opts.headers : {})
      },
      ...(opts || {})
    });

    const text = await res.text().catch(() => "");
    let json = null;

    try {
      json = text ? JSON.parse(text) : null;
    } catch (_) {
      json = null;
    }

    if (!res.ok || !json || json.ok === false) {
      const msg =
          json && (json.message || json.error)
              ? (json.message || json.error)
              : (text ? text.replace(/\s+/g, " ").slice(0, 240) : `HTTP ${res.status}`);

      const err = new Error(msg);
      err.status = res.status;
      err.json = json;
      throw err;
    }

    return json;
  }

  function renderZones(zones) {
    if (!zonesList) return;

    if (!Array.isArray(zones) || zones.length === 0) {
      renderEmpty("No active Drop Zones yet. Create one when you need an outsider upload link.");
      return;
    }

    zonesList.innerHTML = zones.map((z) => {
      const id = z.id || "";
      const name = z.name || id || "Drop Zone";
      const dest = z.destination_path || "—";
      const uploads = Number(z.upload_count || 0);
      const bytes = Number(z.bytes_uploaded || 0);
      const expires = fmtEpoch(z.expires_epoch);
      const maxFile = fmtBytes(z.max_file_bytes || 0);
      const maxTotal = fmtBytes(z.max_total_bytes || 0);
      const disabled = !!z.disabled;

      return `
        <article class="dzCard" data-zone-id="${escapeHtml(id)}">
          <div class="dzCardTop">
            <div>
              <div class="dzCardTitle">${escapeHtml(name)}</div>
              <div class="dzCardMeta">Destination: ${escapeHtml(dest)}</div>
            </div>
            <div class="dzBadge ${disabled ? "bad" : "ok"}">
              ${disabled ? "Disabled" : "Active"}
            </div>
          </div>

          <div class="dzStats">
            <div><span>Uploads</span><strong>${uploads}</strong></div>
            <div><span>Uploaded</span><strong>${escapeHtml(fmtBytes(bytes))}</strong></div>
            <div><span>Expires</span><strong>${escapeHtml(expires)}</strong></div>
          </div>

          <div class="dzCardMeta">Max file: ${escapeHtml(maxFile)} · Total limit: ${escapeHtml(maxTotal)}</div>

          <div class="dzCardActions">
            <button class="dzGhost dzDisableBtn" type="button" data-zone-id="${escapeHtml(id)}">
              Disable
            </button>
          </div>
        </article>
      `;
    }).join("");
  }

  async function loadZones() {
    setStatus("Loading…");
    setBusy(true);

    try {
      const json = await apiJson("/api/v4/dropzones/list");

      const zones = Array.isArray(json.drop_zones)
          ? json.drop_zones
          : (Array.isArray(json.zones) ? json.zones : []);

      setStatus(`${zones.length} active Drop Zone${zones.length === 1 ? "" : "s"}`);
      renderZones(zones);
    } catch (e) {
      if (e && e.status === 404) {
        setStatus("Backend not wired yet.");
        renderEmpty("Drop Zone UI is installed, but /api/v4/dropzones routes are missing.");
      } else {
        setStatus("Could not load Drop Zones.");
        renderEmpty(String(e && e.message ? e.message : e));
      }
    } finally {
      setBusy(false);
    }
  }

  async function createDropZone(ev) {
    ev?.preventDefault?.();

    const name = String(zoneNameInput?.value || "").trim() || "Drop Zone";
    const destinationPath = String(destInput?.value || "").trim();
    const expiresInSeconds = Number(expiryInput?.value || 86400);
    const maxFileBytes = Number(maxFileInput?.value || 0);
    const maxTotalBytes = Number(maxTotalInput?.value || 0);
    const password = String(passwordInput?.value || "");

    if (createResult) {
      createResult.classList.add("hidden");
      createResult.innerHTML = "";
    }

    setCreateBusy(true);

    try {
      const body = {
        name,
        destination_path: destinationPath,
        expires_in_seconds: Number.isFinite(expiresInSeconds) ? expiresInSeconds : 86400,
        max_file_bytes: Number.isFinite(maxFileBytes) ? maxFileBytes : 0,
        max_total_bytes: Number.isFinite(maxTotalBytes) ? maxTotalBytes : 0
      };

      if (password) body.password = password;

      const json = await apiJson("/api/v4/dropzones/create", {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify(body)
      });

      const fullUrl = json.full_url || (json.url ? `${window.location.origin}${json.url}` : "");

      showCreateResult("ok", `
        <div class="dzResultTitle">Drop Zone created</div>
        <div class="dzResultUrl">${escapeHtml(fullUrl || "Link was created, but no URL was returned.")}</div>
        <div class="dzResultActions">
          ${fullUrl ? `<button id="copyCreatedLinkBtn" class="dzGhost" type="button">Copy link</button>` : ""}
          ${fullUrl ? `<button id="openCreatedLinkBtn" class="dzGhost" type="button">Open page</button>` : ""}
        </div>
        <div class="dzHint">
          Save this link now. For security, the raw token is only shown when the Drop Zone is created.
        </div>
      `);

      el("copyCreatedLinkBtn")?.addEventListener("click", async () => {
        const ok = await copyText(fullUrl);
        setStatus(ok ? "Link copied." : "Could not copy link.");
      });

      el("openCreatedLinkBtn")?.addEventListener("click", () => {
        if (fullUrl) window.open(fullUrl, "_blank", "noopener,noreferrer");
      });

      await loadZones();
    } catch (e) {
      showCreateResult("fail", `
        <div class="dzResultTitle">Could not create Drop Zone</div>
        <div>${escapeHtml(e && e.message ? e.message : e)}</div>
      `);
    } finally {
      setCreateBusy(false);
    }
  }

  async function disableZone(id) {
    if (!id) return;

    const ok = confirm("Disable this Drop Zone? Existing public link will stop accepting uploads.");
    if (!ok) return;

    setStatus("Disabling Drop Zone…");
    setBusy(true);

    try {
      await apiJson("/api/v4/dropzones/disable", {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          id,
          disabled: true
        })
      });

      setStatus("Drop Zone disabled.");
      await loadZones();
    } catch (e) {
      setStatus(`Could not disable Drop Zone: ${e && e.message ? e.message : e}`);
    } finally {
      setBusy(false);
    }
  }

  zonesList?.addEventListener("click", (ev) => {
    const disableBtn = ev.target && ev.target.closest
        ? ev.target.closest(".dzDisableBtn")
        : null;

    if (disableBtn) {
      disableZone(disableBtn.getAttribute("data-zone-id") || "");
    }
  });

  refreshBtn?.addEventListener("click", loadZones);
  createBtn?.addEventListener("click", openCreateModal);
  modalCloseBtn?.addEventListener("click", closeCreateModal);
  cancelCreateBtn?.addEventListener("click", closeCreateModal);
  createForm?.addEventListener("submit", createDropZone);

  createModal?.addEventListener("click", (ev) => {
    if (ev.target && ev.target.getAttribute("data-close-modal") === "1") {
      closeCreateModal();
    }
  });

  document.addEventListener("keydown", (ev) => {
    if (ev.key === "Escape" && createModal && !createModal.classList.contains("hidden")) {
      closeCreateModal();
    }
  });

  loadZones();
})();