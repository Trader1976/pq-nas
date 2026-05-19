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
        const j = await r.json();
        const ver = j && typeof j.version === "string" ? j.version.trim() : "";
        if (ver) return ver;
      } catch (_) {}
    }

    return "";
  }

  async function initAppVersion() {
    const versionEl = el("appVersion");
    if (!versionEl) return;

    const ver = await getAppVersion();
    if (!ver) {
      versionEl.hidden = true;
      return;
    }

    versionEl.textContent = `v${ver}`;
    versionEl.title = `Drop Zone ${ver}`;
    versionEl.hidden = false;
  }

  initAppVersion();

  function escapeHtml(s) {
    return String(s == null ? "" : s)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll("\"", "&quot;")
        .replaceAll("'", "&#39;");
  }

  function tr(key, vars = null, fallback = "") {
    try {
      if (window.PQNAS_I18N && typeof window.PQNAS_I18N.t === "function") {
        return window.PQNAS_I18N.t(key, vars, fallback || key);
      }
    } catch (_) {}
    return fallback || key;
  }

  function ensureDropZoneConfirmCss() {
    if (document.getElementById("dropZoneConfirmCss")) return;

    const style = document.createElement("style");
    style.id = "dropZoneConfirmCss";
    style.textContent = `
.dzConfirmBackdrop{
  position:fixed;
  inset:0;
  z-index:100000;
  display:flex;
  align-items:center;
  justify-content:center;
  padding:18px;
  background:rgba(0,0,0,.55);
  backdrop-filter:blur(6px);
  -webkit-backdrop-filter:blur(6px);
}
.dzConfirmCard{
  width:min(560px, calc(100vw - 24px));
  border:1px solid rgba(255,255,255,.18);
  border-radius:18px;
  overflow:hidden;
  background:var(--panel,#181818);
  color:var(--fg,#f5f5f5);
  box-shadow:0 18px 70px rgba(0,0,0,.45);
}
.dzConfirmHead{
  padding:14px 16px;
  border-bottom:1px solid rgba(255,255,255,.12);
  background:rgba(255,255,255,.06);
}
.dzConfirmTitle{
  font-weight:950;
  letter-spacing:.2px;
}
.dzConfirmBody{
  padding:16px;
}
.dzConfirmMessage{
  padding:10px 12px;
  border-radius:14px;
  border:1px solid rgba(255,190,90,.35);
  background:rgba(255,190,90,.10);
  white-space:pre-wrap;
  line-height:1.45;
}
.dzConfirmFoot{
  display:flex;
  justify-content:flex-end;
  gap:10px;
  padding:12px 16px;
  border-top:1px solid rgba(255,255,255,.12);
  background:rgba(255,255,255,.06);
}
.dzConfirmBtn{
  appearance:none;
  border:1px solid rgba(255,255,255,.22);
  border-radius:12px;
  padding:9px 13px;
  font-weight:850;
  cursor:pointer;
  background:rgba(255,255,255,.08);
  color:inherit;
}
.dzConfirmBtn.danger{
  border-color:rgba(180,40,40,.55);
  background:rgba(180,40,40,.18);
}
`;
    document.head.appendChild(style);
  }

  function openDropZoneConfirmModal(opts = {}) {
    ensureDropZoneConfirmCss();

    return new Promise((resolve) => {
      const options = opts || {};

      const modal = document.createElement("div");
      modal.className = "dzConfirmBackdrop";
      modal.setAttribute("role", "dialog");
      modal.setAttribute("aria-modal", "true");

      const card = document.createElement("div");
      card.className = "dzConfirmCard";

      const head = document.createElement("div");
      head.className = "dzConfirmHead";

      const title = document.createElement("div");
      title.className = "dzConfirmTitle";
      title.textContent = options.title || tr("dropzone.confirm.title", null, "Confirm");

      const body = document.createElement("div");
      body.className = "dzConfirmBody";

      const message = document.createElement("div");
      message.className = "dzConfirmMessage";
      message.textContent = options.message || "";

      const foot = document.createElement("div");
      foot.className = "dzConfirmFoot";

      const cancelBtn = document.createElement("button");
      cancelBtn.type = "button";
      cancelBtn.className = "dzConfirmBtn";
      cancelBtn.textContent = options.cancelText || tr("dropzone.cancel", null, "Cancel");

      const okBtn = document.createElement("button");
      okBtn.type = "button";
      okBtn.className = options.danger ? "dzConfirmBtn danger" : "dzConfirmBtn";
      okBtn.textContent = options.confirmText || tr("dropzone.ok", null, "OK");

      head.appendChild(title);
      body.appendChild(message);
      foot.appendChild(cancelBtn);
      foot.appendChild(okBtn);

      card.appendChild(head);
      card.appendChild(body);
      card.appendChild(foot);
      modal.appendChild(card);
      document.body.appendChild(modal);

      const finish = (value) => {
        document.removeEventListener("keydown", onKey, true);
        modal.remove();
        resolve(!!value);
      };

      const onKey = (ev) => {
        if (ev.key === "Escape") {
          ev.preventDefault();
          ev.stopPropagation();
          finish(false);
          return;
        }
        if (ev.key === "Enter") {
          ev.preventDefault();
          ev.stopPropagation();
          finish(true);
        }
      };

      document.addEventListener("keydown", onKey, true);
      modal.addEventListener("click", (ev) => {
        if (ev.target === modal) finish(false);
      });
      cancelBtn.addEventListener("click", () => finish(false));
      okBtn.addEventListener("click", () => finish(true));

      setTimeout(() => cancelBtn.focus(), 0);
    });
  }

  function setStatus(text) {
    if (statusLine) statusLine.textContent = text || "";
  }

  function fmtBytes(n) {
    n = Number(n || 0);
    if (!Number.isFinite(n) || n <= 0) return tr("dropzone.no_limit", null, "No limit");

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
    if (!Number.isFinite(n) || n <= 0) return tr("dropzone.never", null, "Never");

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

    if (zoneNameInput) zoneNameInput.value = tr("dropzone.default_name", null, "Drop Zone");
    if (destInput) destInput.value = tr("dropzone.default_destination", null, "Incoming/Drop Zones/Drop Zone");

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
      renderEmpty(tr("dropzone.empty", null, "No active Drop Zones yet. Create one when you need an outsider upload link."));
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
              <div class="dzCardMeta">${escapeHtml(tr("dropzone.destination", null, "Destination"))}: ${escapeHtml(dest)}</div>
            </div>
            <div class="dzBadge ${disabled ? "bad" : "ok"}">
              ${disabled ? tr("dropzone.disabled", null, "Disabled") : tr("dropzone.active", null, "Active")}
            </div>
          </div>

          <div class="dzStats">
            <div><span>${escapeHtml(tr("dropzone.uploads", null, "Uploads"))}</span><strong>${uploads}</strong></div>
            <div><span>${escapeHtml(tr("dropzone.uploaded", null, "Uploaded"))}</span><strong>${escapeHtml(fmtBytes(bytes))}</strong></div>
            <div><span>${escapeHtml(tr("dropzone.expires", null, "Expires"))}</span><strong>${escapeHtml(expires)}</strong></div>
          </div>

          <div class="dzCardMeta">${escapeHtml(tr("dropzone.max_file", null, "Max file"))}: ${escapeHtml(maxFile)} · ${escapeHtml(tr("dropzone.total_limit", null, "Total limit"))}: ${escapeHtml(maxTotal)}</div>

          <div class="dzCardActions">
            <button class="dzGhost dzDisableBtn" type="button" data-zone-id="${escapeHtml(id)}">
              ${escapeHtml(tr("dropzone.disable", null, "Disable"))}
            </button>
          </div>
        </article>
      `;
    }).join("");
  }

  async function loadZones() {
    setStatus(tr("common.loading", null, "Loading…"));
    setBusy(true);

    try {
      const json = await apiJson("/api/v4/dropzones/list");

      const zones = Array.isArray(json.drop_zones)
          ? json.drop_zones
          : (Array.isArray(json.zones) ? json.zones : []);

      setStatus(tr("dropzone.active_count", { count: zones.length }, `${zones.length} active Drop Zone${zones.length === 1 ? "" : "s"}`));
      renderZones(zones);
    } catch (e) {
      if (e && e.status === 404) {
        setStatus(tr("dropzone.backend_not_wired", null, "Backend not wired yet."));
        renderEmpty(tr("dropzone.routes_missing", null, "Drop Zone UI is installed, but /api/v4/dropzones routes are missing."));
      } else {
        setStatus(tr("dropzone.load_failed", null, "Could not load Drop Zones."));
        renderEmpty(String(e && e.message ? e.message : e));
      }
    } finally {
      setBusy(false);
    }
  }

  async function createDropZone(ev) {
    ev?.preventDefault?.();

    const name = String(zoneNameInput?.value || "").trim() || tr("dropzone.default_name", null, "Drop Zone");
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
        <div class="dzResultTitle">${escapeHtml(tr("dropzone.created_title", null, "Drop Zone created"))}</div>
        <div class="dzResultUrl">${escapeHtml(fullUrl || tr("dropzone.no_url_returned", null, "Link was created, but no URL was returned."))}</div>
        <div class="dzResultActions">
          ${fullUrl ? `<button id="copyCreatedLinkBtn" class="dzGhost" type="button">${escapeHtml(tr("dropzone.copy_link", null, "Copy link"))}</button>` : ""}
          ${fullUrl ? `<button id="openCreatedLinkBtn" class="dzGhost" type="button">${escapeHtml(tr("dropzone.open_page", null, "Open page"))}</button>` : ""}
        </div>
        <div class="dzHint">
          ${escapeHtml(tr("dropzone.save_link_hint", null, "Save this link now. For security, the raw token is only shown when the Drop Zone is created."))}
        </div>
      `);

      el("copyCreatedLinkBtn")?.addEventListener("click", async () => {
        const ok = await copyText(fullUrl);
        setStatus(ok ? tr("dropzone.link_copied", null, "Link copied.") : tr("dropzone.copy_failed", null, "Could not copy link."));
      });

      el("openCreatedLinkBtn")?.addEventListener("click", () => {
        if (fullUrl) window.open(fullUrl, "_blank", "noopener,noreferrer");
      });

      await loadZones();
    } catch (e) {
      showCreateResult("fail", `
        <div class="dzResultTitle">${escapeHtml(tr("dropzone.create_failed", null, "Could not create Drop Zone"))}</div>
        <div>${escapeHtml(e && e.message ? e.message : e)}</div>
      `);
    } finally {
      setCreateBusy(false);
    }
  }

  async function disableZone(id) {
    if (!id) return;

    const ok = await openDropZoneConfirmModal({
      title: tr("dropzone.disable.title", null, "Disable this Drop Zone?"),
      message: tr("dropzone.disable.message", null, "Existing public link will stop accepting uploads."),
      confirmText: tr("dropzone.disable.confirm", null, "Disable"),
      cancelText: tr("dropzone.cancel", null, "Cancel"),
      danger: true
    });
    if (!ok) return;

    setStatus(tr("dropzone.disabling", null, "Disabling Drop Zone…"));
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

      setStatus(tr("dropzone.disabled_status", null, "Drop Zone disabled."));
      await loadZones();
    } catch (e) {
      setStatus(tr("dropzone.disable_failed", { error: String(e && e.message ? e.message : e) }, `Could not disable Drop Zone: ${e && e.message ? e.message : e}`));
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

  function startDropZoneApp() {
    try {
      if (window.PQNAS_I18N && typeof window.PQNAS_I18N.apply === "function") {
        window.PQNAS_I18N.apply(document);
      }
    } catch (_) {}
    loadZones();
  }

  window.addEventListener("pqnas-language-changed", () => {
    try {
      if (window.PQNAS_I18N && typeof window.PQNAS_I18N.apply === "function") {
        window.PQNAS_I18N.apply(document);
      }
    } catch (_) {}
    loadZones();
  });

  if (window.PQNAS_I18N && typeof window.PQNAS_I18N.ready === "function") {
    window.PQNAS_I18N.ready().then(startDropZoneApp).catch(startDropZoneApp);
  } else {
    startDropZoneApp();
  }
})();