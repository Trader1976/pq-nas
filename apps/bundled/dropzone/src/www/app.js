(() => {
  "use strict";

  const el = (id) => document.getElementById(id);

  const statusLine = el("statusLine");
  const zonesList = el("zonesList");
  const refreshBtn = el("refreshBtn");
  const createBtn = el("createBtn");

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

  function renderEmpty(message) {
    if (!zonesList) return;
    zonesList.innerHTML = `<div class="dzEmpty">${escapeHtml(message)}</div>`;
  }

  function renderZones(zones) {
    if (!zonesList) return;

    if (!Array.isArray(zones) || zones.length === 0) {
      renderEmpty("No Drop Zones yet. Create one when the backend route is wired.");
      return;
    }

    zonesList.innerHTML = zones.map((z) => {
      const name = z.name || z.id || "Drop Zone";
      const dest = z.destination_path || "—";
      const uploads = Number(z.upload_count || 0);
      const bytes = Number(z.bytes_uploaded || 0);

      return `
        <article class="dzCard">
          <div class="dzCardTitle">${escapeHtml(name)}</div>
          <div class="dzCardMeta">Destination: ${escapeHtml(dest)}</div>
          <div class="dzCardMeta">Uploads: ${uploads} · Bytes: ${bytes}</div>
        </article>
      `;
    }).join("");
  }

  async function loadZones() {
    setStatus("Loading…");

    try {
      const res = await fetch("/api/v4/dropzones/list", {
        credentials: "include",
        cache: "no-store"
      });

      const json = await res.json().catch(() => null);

      if (res.status === 404) {
        setStatus("Backend not wired yet.");
        renderEmpty("Drop Zone UI is installed. Next step: add /api/v4/dropzones routes.");
        return;
      }

      if (!res.ok || !json || json.ok === false) {
        throw new Error((json && (json.message || json.error)) || `HTTP ${res.status}`);
      }

      const zones = Array.isArray(json.drop_zones)
        ? json.drop_zones
        : (Array.isArray(json.zones) ? json.zones : []);

      setStatus(`${zones.length} Drop Zone${zones.length === 1 ? "" : "s"}`);
      renderZones(zones);
    } catch (e) {
      setStatus("Could not load Drop Zones.");
      renderEmpty(String(e && e.message ? e.message : e));
    }
  }

  if (refreshBtn) refreshBtn.addEventListener("click", loadZones);

  if (createBtn) {
    createBtn.addEventListener("click", () => {
      renderEmpty("Create dialog comes next. First we wire the backend storage and token model.");
      setStatus("Create flow not wired yet.");
    });
  }

  loadZones();
})();
