(() => {
  "use strict";

  const VIDEO_EXTS = new Set([
    "mp4", "m4v", "mov", "webm", "mkv", "avi", "wmv", "flv", "mpeg", "mpg", "3gp"
  ]);

  const el = (id) => document.getElementById(id);

  const grid = el("grid");
  const emptyState = el("emptyState");
  const statusText = el("statusText");
  const countText = el("countText");
  const filterInput = el("filterInput");
  const scanBtn = el("scanBtn");
  const searchBtn = el("searchBtn");

  const modal = el("playerModal");
  const player = el("player");
  const playerTitle = el("playerTitle");
  const playerPath = el("playerPath");
  const closePlayerBtn = el("closePlayerBtn");

  let allVideos = [];
  const metaCache = new Map();
  const metaInFlight = new Set();

  let selectedPath = "";

  function isTypingTarget(target) {
    if (!target) return false;
    if (target.isContentEditable) return true;

    const tag = String(target.tagName || "").toUpperCase();
    return tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT";
  }

  function reelCardNodes() {
    return Array.from(document.querySelectorAll(".rsCard[data-rs-path]"));
  }

  function applySelectedCardStyles() {
    for (const node of reelCardNodes()) {
      const on = node.dataset.rsPath === selectedPath;
      node.classList.toggle("rsSelected", on);
      node.setAttribute("aria-selected", on ? "true" : "false");
    }
  }

  function focusSelectedCard() {
    if (!selectedPath) return;

    const node = reelCardNodes().find(n => n.dataset.rsPath === selectedPath);
    if (!node) return;

    try {
      node.focus({ preventScroll: true });
      node.scrollIntoView({ block: "nearest", inline: "nearest" });
    } catch (_) {
      node.focus();
    }
  }

  function setSelectedPath(path, opts) {
    selectedPath = String(path || "");
    applySelectedCardStyles();

    if (opts && opts.focus) {
      focusSelectedCard();
    }
  }

  function selectedVideo() {
    if (selectedPath) {
      const found = allVideos.find(v => v && v.path === selectedPath);
      if (found) return found;
    }

    const visible = filteredVideos();
    return visible.length ? visible[0] : null;
  }

  function ensureSelectionForVideos(videos) {
    if (!Array.isArray(videos) || !videos.length) {
      selectedPath = "";
      return;
    }

    if (!selectedPath || !videos.some(v => v && v.path === selectedPath)) {
      selectedPath = videos[0].path || "";
    }
  }

  function selectedIndexIn(videos) {
    if (!Array.isArray(videos) || !videos.length) return -1;
    const idx = videos.findIndex(v => v && v.path === selectedPath);
    return idx >= 0 ? idx : 0;
  }

  function reelGridColumnCount() {
    const nodes = reelCardNodes();
    if (!nodes.length) return 1;

    const firstTop = nodes[0].getBoundingClientRect().top;
    let count = 0;

    for (const node of nodes) {
      const top = node.getBoundingClientRect().top;
      if (Math.abs(top - firstTop) <= 8) count++;
      else break;
    }

    return Math.max(1, count || 1);
  }

  function moveSelection(delta) {
    const videos = filteredVideos();
    if (!videos.length) return;

    ensureSelectionForVideos(videos);

    const cur = selectedIndexIn(videos);
    const next = Math.max(0, Math.min(videos.length - 1, cur + delta));
    setSelectedPath(videos[next].path, { focus: true });
  }

  function handleReelStackKeydown(ev) {
    const typing = isTypingTarget(ev.target);

    if ((ev.ctrlKey || ev.metaKey) && String(ev.key || "").toLowerCase() === "s") {
      if (metaEditor && !metaEditor.hidden) {
        ev.preventDefault();
        saveMetaEditor();
      }
      return;
    }

    if (ev.key === "Escape") {
      if (metaEditor && !metaEditor.hidden) {
        ev.preventDefault();
        ev.stopPropagation();
        closeMetaEditor();
        return;
      }

      if (modal && !modal.hidden) {
        ev.preventDefault();
        ev.stopPropagation();
        closePlayer();
        return;
      }
    }

    if (typing) return;

    if (modal && !modal.hidden) return;

    if (ev.key === " " || ev.key === "Spacebar") {
      const v = selectedVideo();

      if (metaEditor && !metaEditor.hidden) {
        ev.preventDefault();
        ev.stopPropagation();
        closeMetaEditor();
        return;
      }

      if (v) {
        ev.preventDefault();
        editVideoMetadata(v);
      }
      return;
    }

    if (metaEditor && !metaEditor.hidden) return;

    const videos = filteredVideos();
    if (!videos.length) return;

    if (ev.key === "ArrowRight") {
      ev.preventDefault();
      moveSelection(1);
    } else if (ev.key === "ArrowLeft") {
      ev.preventDefault();
      moveSelection(-1);
    } else if (ev.key === "ArrowDown") {
      ev.preventDefault();
      moveSelection(reelGridColumnCount());
    } else if (ev.key === "ArrowUp") {
      ev.preventDefault();
      moveSelection(-reelGridColumnCount());
    } else if (ev.key === "Home") {
      ev.preventDefault();
      setSelectedPath(videos[0].path, { focus: true });
    } else if (ev.key === "End") {
      ev.preventDefault();
      setSelectedPath(videos[videos.length - 1].path, { focus: true });
    }
  }


  function setStatus(text) {
    if (statusText) statusText.textContent = text || "";
  }

  function fmtBytes(n) {
    n = Number(n || 0);
    if (!Number.isFinite(n) || n <= 0) return "0 B";
    const units = ["B", "KB", "MB", "GB", "TB"];
    let i = 0;
    while (n >= 1024 && i < units.length - 1) {
      n /= 1024;
      i++;
    }
    return `${n.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
  }

  function basename(path) {
    const s = String(path || "");
    const p = s.split("/").filter(Boolean);
    return p.length ? p[p.length - 1] : "";
  }

  function extOf(name) {
    const s = String(name || "");
    const i = s.lastIndexOf(".");
    return i >= 0 ? s.slice(i + 1).toLowerCase() : "";
  }

  function joinPath(parent, name) {
    parent = String(parent || "").replace(/^\/+|\/+$/g, "");
    name = String(name || "").replace(/^\/+|\/+$/g, "");
    if (!parent) return name;
    if (!name) return parent;
    return `${parent}/${name}`;
  }

  function fileStreamUrl(path) {
    // File Manager video preview uses /api/v4/files/get for preview/open.
    return `/api/v4/files/get?path=${encodeURIComponent(path || "")}`;
  }

  function fileDownloadUrl(path) {
    return `/api/v4/files/get?path=${encodeURIComponent(path || "")}&download=1`;
  }

  function fileThumbUrl(path) {
    return `/api/v4/reelstack/thumb?path=${encodeURIComponent(path || "")}&size=480`;
  }


  function fileMetaUrl(path) {
    return `/api/v4/reelstack/meta?path=${encodeURIComponent(path || "")}`;
  }

  function fileUserMetaUrl(path) {
    return `/api/v4/reelstack/user_meta?path=${encodeURIComponent(path || "")}`;
  }

  function fileUserMetaSetUrl() {
    return "/api/v4/reelstack/meta/set";
  }

  function videoMimeForName(name) {
    const ext = extOf(name);
    if (ext === "mp4" || ext === "m4v") return "video/mp4";
    if (ext === "webm") return "video/webm";
    if (ext === "ogv" || ext === "ogg") return "video/ogg";
    if (ext === "mov") return "video/quicktime";
    return "video/mp4";
  }

  function fileDeleteUrl(path) {
    return `/api/v4/files/delete?path=${encodeURIComponent(path)}`;
  }

  function fileMoveUrl(from, to) {
    const qs = new URLSearchParams();
    qs.set("from", from || "");
    qs.set("to", to || "");
    return `/api/v4/files/move?${qs.toString()}`;
  }

  function dirnameOf(path) {
    const s = String(path || "").replace(/^\/+|\/+$/g, "");
    const i = s.lastIndexOf("/");
    return i >= 0 ? s.slice(0, i) : "";
  }

  async function apiJson(url, opts) {
    const r = await fetch(url, Object.assign({
      cache: "no-store",
      credentials: "include",
      headers: { "Accept": "application/json" }
    }, opts || {}));

    const j = await r.json().catch(() => ({}));
    if (!r.ok || j.ok === false) {
      throw new Error(j.message || j.error || `HTTP ${r.status}`);
    }
    return j;
  }

  function fmtBitrate(n) {
    n = Number(n || 0);
    if (!Number.isFinite(n) || n <= 0) return "";
    if (n >= 1000000) return `${(n / 1000000).toFixed(1)} Mbps`;
    if (n >= 1000) return `${(n / 1000).toFixed(0)} Kbps`;
    return `${Math.round(n)} bps`;
  }

  function fmtFps(n) {
    n = Number(n || 0);
    if (!Number.isFinite(n) || n <= 0) return "";
    return `${n.toFixed(n >= 10 ? 0 : 1)} fps`;
  }

  function metaForVideo(v) {
    if (!v || !v.path) return null;
    return v.meta || metaCache.get(v.path) || null;
  }

  function defaultUserMeta() {
    return {
      title: "",
      tags: [],
      tags_text: "",
      notes: "",
      rating: 0,
      watched: false,
      favorite: false
    };
  }

  function normalizeUserMeta(meta) {
    const out = defaultUserMeta();
    if (!meta || typeof meta !== "object") return out;

    out.title = String(meta.title || "");
    out.tags_text = String(meta.tags_text || "");
    out.notes = String(meta.notes || "");
    out.rating = Math.max(0, Math.min(5, Number(meta.rating || 0) || 0));
    out.watched = !!meta.watched;
    out.favorite = !!meta.favorite;

    if (Array.isArray(meta.tags)) {
      out.tags = meta.tags.map(x => String(x || "").trim()).filter(Boolean);
    } else if (out.tags_text) {
      out.tags = out.tags_text.split(",").map(x => x.trim()).filter(Boolean);
    }

    if (!out.tags_text && out.tags.length) out.tags_text = out.tags.join(", ");

    return out;
  }

  function userMetaForVideo(v) {
    const m = metaForVideo(v);
    if (!m || m._error) return defaultUserMeta();
    return normalizeUserMeta(m.user || m.user_meta || {});
  }

  function videoDisplayTitle(v) {
    const u = userMetaForVideo(v);
    const title = String(u.title || "").trim();
    return title || String(v && v.name || basename(v && v.path || "") || "Video");
  }

  function userMetaSummaryBits(v) {
    const u = userMetaForVideo(v);
    const bits = [];

    // favorite is shown as the top-left badge, so do not repeat it in the summary line.
    if (u.watched) bits.push("watched");
    if (u.rating > 0) bits.push("★".repeat(Math.max(0, Math.min(5, Math.round(u.rating)))));

    if (u.tags && u.tags.length) {
      bits.push(u.tags.slice(0, 3).map(t => "#" + t).join(" "));
    }

    return bits.join(" · ");
  }

  function techMetaLines(v) {
    const m = metaForVideo(v) || {};
    const u = userMetaForVideo(v);
    const lines = [];

    const add = (label, value) => {
      value = String(value === undefined || value === null ? "" : value).trim();
      if (value) lines.push({ label, value });
    };

    add("Duration", m.duration_text || (m.duration_seconds ? `${Math.round(Number(m.duration_seconds))} sec` : ""));
    add("Resolution", m.resolution || ((m.width && m.height) ? `${m.width}x${m.height}` : ""));
    add("FPS", m.fps ? fmtFps(m.fps).replace(/ fps$/i, "") : "");
    add("Video codec", [m.video_codec ? String(m.video_codec).toUpperCase() : "", m.video_codec_long].filter(Boolean).join(" — "));
    add("Audio codec", [m.audio_codec ? String(m.audio_codec).toUpperCase() : "", m.audio_codec_long].filter(Boolean).join(" — "));
    add("Bitrate", m.bit_rate ? fmtBitrate(m.bit_rate) : "");
    add("Format", m.format_long || m.format || "");
    add("Size", fmtBytes(m.size_bytes || v.size_bytes || 0));
    add("Path", "/" + String(v.path || ""));
    if (u.updated_epoch) add("User metadata updated", new Date(Number(u.updated_epoch) * 1000).toLocaleString());

    return lines;
  }

  function fillTechnicalMetaBox(v) {
    const box = metaEditorEl("rsMetaTechnical");
    if (!box) return;

    box.innerHTML = "";

    const lines = techMetaLines(v);
    if (!lines.length) {
      const empty = document.createElement("div");
      empty.className = "rsMetaTechEmpty";
      empty.textContent = "Technical metadata is not available yet.";
      box.appendChild(empty);
      return;
    }

    for (const line of lines) {
      const row = document.createElement("div");
      row.className = "rsMetaTechRow";

      const label = document.createElement("div");
      label.className = "rsMetaTechLabel";
      label.textContent = line.label;

      const value = document.createElement("div");
      value.className = "rsMetaTechValue";
      value.textContent = line.value;

      row.appendChild(label);
      row.appendChild(value);
      box.appendChild(row);
    }
  }


  function videoMetaSummary(v) {
    const m = metaForVideo(v);
    if (!m) return "Metadata loading…";
    if (m._error) return `Metadata unavailable: ${m._error}`;

    const parts = [];
    if (m.resolution) parts.push(m.resolution);
    if (m.fps) parts.push(fmtFps(m.fps));
    if (m.video_codec) parts.push(String(m.video_codec).toUpperCase());
    if (m.audio_codec) parts.push(`audio ${String(m.audio_codec).toUpperCase()}`);
    if (m.bit_rate) parts.push(fmtBitrate(m.bit_rate));

    const tech = parts.filter(Boolean).join(" · ");
    const userBits = userMetaSummaryBits(v);
    return [userBits, tech].filter(Boolean).join(" · ") || "No metadata";
  }

  function durationBadgeText(v) {
    const m = metaForVideo(v);
    if (!m || m._error || !m.duration_text) return "";
    return String(m.duration_text);
  }

  function favoriteBadgeText(v) {
    const u = userMetaForVideo(v);
    return u.favorite ? "★ favorite" : "";
  }


  function updateMetaEls(path) {
    for (const node of document.querySelectorAll("[data-rs-title-path]")) {
      if (node.dataset.rsTitlePath === path) {
        const v = allVideos.find(x => x.path === path) || { path };
        node.textContent = videoDisplayTitle(v);
      }
    }

    for (const node of document.querySelectorAll("[data-rs-meta-path]")) {
      if (node.dataset.rsMetaPath === path) {
        const v = allVideos.find(x => x.path === path) || { path };
        node.textContent = videoMetaSummary(v);
      }
    }

    for (const node of document.querySelectorAll("[data-rs-duration-path]")) {
      if (node.dataset.rsDurationPath === path) {
        const v = allVideos.find(x => x.path === path) || { path };
        const txt = durationBadgeText(v);
        node.textContent = txt;
        node.style.display = txt ? "" : "none";
      }
    }
  
    for (const node of document.querySelectorAll("[data-rs-favorite-path]")) {
      if (node.dataset.rsFavoritePath === path) {
        const v = allVideos.find(x => x.path === path) || { path };
        const txt = favoriteBadgeText(v);
        node.textContent = txt;
        node.style.display = txt ? "" : "none";
      }
    }

}

  async function ensureVideoMeta(v) {
    if (!v || !v.path) return;

    if (metaCache.has(v.path)) {
      v.meta = metaCache.get(v.path);
      updateMetaEls(v.path);
      return;
    }

    if (metaInFlight.has(v.path)) return;
    metaInFlight.add(v.path);

    try {
      const [tech, userResp] = await Promise.all([
        apiJson(fileMetaUrl(v.path)),
        apiJson(fileUserMetaUrl(v.path)).catch(() => ({ ok: false, meta: null }))
      ]);

      const merged = Object.assign({}, tech || {});
      merged.user = normalizeUserMeta(userResp && userResp.meta ? userResp.meta : null);
      merged.user_meta = merged.user;

      metaCache.set(v.path, merged);
      v.meta = merged;
      updateMetaEls(v.path);
    } catch (e) {
      const err = { _error: String(e && e.message ? e.message : e) };
      metaCache.set(v.path, err);
      v.meta = err;
      updateMetaEls(v.path);
    } finally {
      metaInFlight.delete(v.path);
    }
  }

  function queueMetadataLoads(videos) {
    const list = Array.isArray(videos) ? videos.slice(0, 48) : [];
    if (!list.length) return;

    window.setTimeout(() => {
      for (const v of list) {
        if (v && v.path && !metaCache.has(v.path)) {
          ensureVideoMeta(v);
        }
      }
    }, 0);
  }

  function extractItems(j) {
    if (Array.isArray(j.items)) return j.items;
    if (Array.isArray(j.entries)) return j.entries;
    if (Array.isArray(j.files)) return j.files;
    return [];
  }

  function itemName(item) {
    return item.name || item.filename || basename(item.path || item.rel_path || "");
  }

  function itemPath(parent, item) {
    const direct = item.path || item.rel_path || item.logical_rel_path;
    if (typeof direct === "string" && direct.length) return direct.replace(/^\/+/, "");
    return joinPath(parent, itemName(item));
  }

  function isDir(item) {
    const t = String(item.type || item.kind || "").toLowerCase();
    return t === "dir" || t === "directory" || item.is_dir === true;
  }

  function isFile(item) {
    const t = String(item.type || item.kind || "").toLowerCase();
    return t === "file" || item.is_file === true || (!isDir(item) && itemName(item));
  }

  async function listFolder(path) {
    const url = `/api/v4/files/list?path=${encodeURIComponent(path || "")}`;
    const j = await apiJson(url);
    return extractItems(j);
  }

  function normalizeVideoItem(item) {
    item = item || {};

    const directPath = item.path || item.rel_path || item.logical_rel_path || "";
    const path = String(directPath || "").replace(/^\/+/, "");
    const name = item.name || item.filename || basename(path);

    return {
      name,
      path,
      size_bytes: Number(item.size_bytes || item.size || 0),
      mtime_epoch: Number(item.mtime_epoch || item.modified_epoch || 0),
      duration_seconds: Number(item.duration_seconds || 0),
      width: Number(item.width || 0),
      height: Number(item.height || 0),
      source: item.source || ""
    };
  }

  function applyIndexResponse(j, verb) {
    const items = extractItems(j)
      .map(normalizeVideoItem)
      .filter(v => v.path && VIDEO_EXTS.has(extOf(v.name || v.path)));

    allVideos = items;
    render();

    const stats = j && j.stats ? j.stats : {};
    const generated = Number(j && j.generated_at_epoch || 0);
    const warningCount = Array.isArray(j && j.warnings) ? j.warnings.length : 0;
    const truncated = !!stats.truncated;

    if (!generated && !items.length) {
      setStatus("No saved Reel Stack index yet. Click Refresh index.");
      return;
    }

    const parts = [
      `${verb || "Loaded"} ${items.length} video${items.length === 1 ? "" : "s"}`
    ];

    if (Number.isFinite(Number(stats.files_seen)) && Number(stats.files_seen) > 0) {
      parts.push(`checked ${Number(stats.files_seen)} file${Number(stats.files_seen) === 1 ? "" : "s"}`);
    }

    if (generated > 0) {
      parts.push(`indexed ${new Date(generated * 1000).toLocaleString()}`);
    }

    if (truncated) parts.push("truncated");
    if (warningCount) parts.push(`${warningCount} warning${warningCount === 1 ? "" : "s"}`);

    setStatus(parts.join(" · "));
  }

  async function loadIndex() {
    setStatus("Loading saved Reel Stack index…");
    const j = await apiJson("/api/v4/reelstack/index");
    applyIndexResponse(j, "Loaded");
  }

  async function scanVideos() {
    if (scanBtn) {
      scanBtn.disabled = true;
      scanBtn.textContent = "Refreshing…";
    }

    try {
      setStatus("Refreshing Reel Stack index…");

      const j = await apiJson("/api/v4/reelstack/scan", {
        method: "POST",
        headers: {
          "Accept": "application/json",
          "Content-Type": "application/json"
        },
        body: "{}"
      });

      applyIndexResponse(j, "Refreshed");
    } catch (e) {
      setStatus(`Refresh failed: ${e && e.message ? e.message : String(e)}`);
    } finally {
      if (scanBtn) {
        scanBtn.disabled = false;
        scanBtn.textContent = "Refresh index";
      }
    }
  }

  function currentFilter() {
    return String(filterInput && filterInput.value || "").trim().toLowerCase();
  }

  function currentSearchTerms() {
    return currentFilter()
      .split(/\s+/)
      .map(x => x.trim().toLowerCase())
      .filter(Boolean);
  }

  function videoSearchHaystack(v) {
    const m = metaForVideo(v) || {};
    const u = userMetaForVideo(v);

    return [
      v && v.name,
      v && v.path,
      u.title,
      u.tags_text,
      Array.isArray(u.tags) ? u.tags.join(" ") : "",
      u.notes,
      u.watched ? "watched" : "",
      u.favorite ? "favorite" : "",
      u.rating ? "rating " + u.rating + " " + "★".repeat(Math.max(0, Math.min(5, Math.round(u.rating)))) : "",
      m.duration_text,
      m.resolution,
      m.video_codec,
      m.video_codec_long,
      m.audio_codec,
      m.audio_codec_long,
      m.format,
      m.format_long,
      m.fps ? fmtFps(m.fps) : "",
      m.bit_rate ? fmtBitrate(m.bit_rate) : ""
    ].filter(Boolean).join(" ").toLowerCase();
  }

  function filteredVideos() {
    const terms = currentSearchTerms();
    if (!terms.length) return allVideos;

    return allVideos.filter(v => {
      const haystack = videoSearchHaystack(v);
      return terms.every(term => haystack.includes(term));
    });
  }

  function applySearchQuery(query) {
    const q = String(query || "").trim();

    if (filterInput) filterInput.value = q;

    const videos = filteredVideos();
    ensureSelectionForVideos(videos);
    render();

    if (q) {
      setStatus(`Search "${q}" · ${videos.length} video${videos.length === 1 ? "" : "s"}`);
    } else {
      setStatus(`Search cleared · ${allVideos.length} video${allVideos.length === 1 ? "" : "s"}`);
    }
  }

  function openSearchModal() {
    const api = window.PQNAS_REELSTACK_SEARCH;

    if (!api || typeof api.open !== "function") {
      try { filterInput?.focus(); } catch (_) {}
      return;
    }

    api.open({
      initialQuery: currentFilter(),
      onApply: applySearchQuery,
      onClear: () => applySearchQuery("")
    });
  }

  function render() {
    const videos = filteredVideos();
    ensureSelectionForVideos(videos);

    if (countText) {
      countText.textContent = `${videos.length} video${videos.length === 1 ? "" : "s"}`;
    }

    if (!grid) return;
    grid.innerHTML = "";

    if (emptyState) {
      emptyState.style.display = allVideos.length ? "none" : "";
    }

    for (const v of videos) {
      const card = document.createElement("article");
      card.className = "rsCard";
      card.tabIndex = 0;
      card.dataset.rsPath = v.path || "";
      card.setAttribute("role", "option");
      card.setAttribute("aria-selected", (v.path === selectedPath) ? "true" : "false");
      if (v.path === selectedPath) card.classList.add("rsSelected");
      card.addEventListener("click", () => setSelectedPath(v.path));
      card.addEventListener("focusin", () => setSelectedPath(v.path));

      const thumb = document.createElement("div");
      thumb.className = "rsThumb rsThumbPlaceholder";

      const icon = document.createElement("div");
      icon.className = "rsVideoIcon";
      icon.textContent = "▶";

      const img = document.createElement("img");
      img.loading = "lazy";
      img.decoding = "async";
      img.alt = "";
      img.addEventListener("load", () => {
        thumb.classList.remove("rsThumbPlaceholder");
      });
      img.addEventListener("error", () => {
        try { img.remove(); } catch (_) {}
        thumb.classList.add("rsThumbPlaceholder");
      }, { once: true });
      img.src = fileThumbUrl(v.path);

      const play = document.createElement("button");
      play.className = "rsPlay";
      play.type = "button";
      play.textContent = "▶";
      play.title = "Play";
      play.addEventListener("click", () => openPlayer(v));

      thumb.appendChild(img);

      const favoriteBadge = document.createElement("div");
      favoriteBadge.className = "rsFavoriteBadge";
      favoriteBadge.dataset.rsFavoritePath = v.path;
      favoriteBadge.textContent = favoriteBadgeText(v);
      favoriteBadge.style.display = favoriteBadge.textContent ? "" : "none";
      thumb.appendChild(favoriteBadge);

      const durationBadge = document.createElement("div");
      durationBadge.className = "rsDurationBadge";
      durationBadge.dataset.rsDurationPath = v.path;
      durationBadge.textContent = durationBadgeText(v);
      durationBadge.style.display = durationBadge.textContent ? "" : "none";

      thumb.appendChild(icon);
      thumb.appendChild(play);
      thumb.appendChild(durationBadge);

      const body = document.createElement("div");
      body.className = "rsBody";

      const title = document.createElement("div");
      title.className = "rsTitle";
      title.dataset.rsTitlePath = v.path;
      title.textContent = videoDisplayTitle(v);
      title.title = v.name;

      const meta = document.createElement("div");
      meta.className = "rsMeta";
      meta.textContent = `${fmtBytes(v.size_bytes)} · /${v.path}`;

      const details = document.createElement("div");
      details.className = "rsDetails";
      details.dataset.rsMetaPath = v.path;
      details.textContent = videoMetaSummary(v);

      const actions = document.createElement("div");
      actions.className = "rsCardActions";

      const openBtn = document.createElement("button");
      openBtn.className = "rsBtn";
      openBtn.type = "button";
      openBtn.textContent = "Play";
      openBtn.addEventListener("click", () => openPlayer(v));

      const dl = document.createElement("a");
      dl.className = "rsBtn";
      dl.textContent = "Download";
      dl.href = fileDownloadUrl(v.path);
      dl.download = v.name;

      const editBtn = document.createElement("button");
      editBtn.className = "rsBtn";
      editBtn.type = "button";
      editBtn.textContent = "Edit";
      editBtn.addEventListener("click", () => editVideoMetadata(v));

      const delBtn = document.createElement("button");
      delBtn.className = "rsBtn";
      delBtn.type = "button";
      delBtn.textContent = "Delete";
      delBtn.addEventListener("click", () => deleteVideo(v));

      actions.appendChild(openBtn);
      actions.appendChild(dl);
      actions.appendChild(editBtn);
      actions.appendChild(delBtn);

      body.appendChild(title);
      body.appendChild(meta);
      body.appendChild(details);
      body.appendChild(actions);

      card.appendChild(thumb);
      card.appendChild(body);
      grid.appendChild(card);
    }

    queueMetadataLoads(videos);
  }

  function openPlayer(v) {
    if (!modal || !player) return;

    player.pause();
    player.innerHTML = "";
    player.removeAttribute("src");
    player.load();

    playerTitle.textContent = v.name || "Video";
    playerPath.textContent = "/" + (v.path || "");

    const source = document.createElement("source");
    source.src = fileStreamUrl(v.path);
    source.type = videoMimeForName(v.name || v.path || "");
    player.appendChild(source);

    modal.hidden = false;
    player.load();
    player.focus();
  }

  function closePlayer() {
    if (!modal || !player) return;
    player.pause();
    player.innerHTML = "";
    player.removeAttribute("src");
    player.load();
    modal.hidden = true;
  }

  let metaEditor = null;
  let metaEditVideo = null;

  function ensureMetaEditor() {
    if (metaEditor) return metaEditor;

    const backdrop = document.createElement("div");
    backdrop.className = "rsMetaEditorBackdrop";
    backdrop.hidden = true;

    const card = document.createElement("div");
    card.className = "rsMetaEditorCard";
    card.setAttribute("role", "dialog");
    card.setAttribute("aria-modal", "true");
    card.setAttribute("aria-label", "Edit Reel Stack metadata");

    card.innerHTML = `
      <div class="rsMetaEditorHead">
        <div>
          <div class="rsMetaEditorKicker">Reel Stack metadata</div>
          <h2>Edit video</h2>
          <p id="rsMetaEditorPath"></p>
        </div>
        <button id="rsMetaEditorClose" class="rsBtn" type="button">Close</button>
      </div>

      <div class="rsMetaEditorGrid">
        <label class="rsField rsFieldWide">
          <span>Title</span>
          <input id="rsMetaTitle" class="rsInput" type="text" maxlength="240" placeholder="Blank = filename">
        </label>

        <label class="rsField rsFieldWide">
          <span>Tags</span>
          <input id="rsMetaTags" class="rsInput" type="text" maxlength="1000" placeholder="family, archive, drone">
        </label>

        <label class="rsField">
          <span>Rating</span>
          <select id="rsMetaRating" class="rsInput">
            <option value="0">No rating</option>
            <option value="1">★</option>
            <option value="2">★★</option>
            <option value="3">★★★</option>
            <option value="4">★★★★</option>
            <option value="5">★★★★★</option>
          </select>
        </label>

        <label class="rsCheckField">
          <input id="rsMetaFavorite" type="checkbox">
          <span>Favorite</span>
        </label>

        <label class="rsCheckField">
          <input id="rsMetaWatched" type="checkbox">
          <span>Watched</span>
        </label>

        <label class="rsField rsFieldWide">
          <span>Notes</span>
          <textarea id="rsMetaNotes" class="rsInput" maxlength="8000" rows="7" placeholder="Add notes about this video…"></textarea>
        </label>
      </div>

        <section class="rsMetaTechPanel rsFieldWide" aria-label="Technical video metadata">
          <div class="rsMetaTechTitle">Technical metadata</div>
          <div id="rsMetaTechnical" class="rsMetaTechGrid"></div>
        </section>

      <div class="rsMetaEditorActions">
        <button id="rsMetaEditorCancel" class="rsBtn" type="button">Cancel</button>
        <button id="rsMetaEditorSave" class="rsBtn primary" type="button" title="Save metadata (Ctrl+S)" aria-keyshortcuts="Control+S Meta+S">Save metadata</button>
      </div>
    `;

    backdrop.appendChild(card);
    document.body.appendChild(backdrop);

    const close = () => closeMetaEditor();

    backdrop.addEventListener("click", (ev) => {
      if (ev.target === backdrop) close();
    });

    card.querySelector("#rsMetaEditorClose")?.addEventListener("click", close);
    card.querySelector("#rsMetaEditorCancel")?.addEventListener("click", close);
    card.querySelector("#rsMetaEditorSave")?.addEventListener("click", saveMetaEditor);

    metaEditor = backdrop;
    return metaEditor;
  }

  function metaEditorEl(id) {
    return metaEditor ? metaEditor.querySelector("#" + id) : null;
  }

  function openMetaEditorFor(v) {
    ensureMetaEditor();
    metaEditVideo = v;

    const current = userMetaForVideo(v);

    const pathEl = metaEditorEl("rsMetaEditorPath");
    const titleEl = metaEditorEl("rsMetaTitle");
    const tagsEl = metaEditorEl("rsMetaTags");
    const notesEl = metaEditorEl("rsMetaNotes");
    const ratingEl = metaEditorEl("rsMetaRating");
    const favoriteEl = metaEditorEl("rsMetaFavorite");
    const watchedEl = metaEditorEl("rsMetaWatched");

    if (pathEl) pathEl.textContent = "/" + (v.path || "");
    if (titleEl) titleEl.value = current.title || "";
    if (tagsEl) tagsEl.value = current.tags_text || (current.tags || []).join(", ");
    if (notesEl) notesEl.value = current.notes || "";
    if (ratingEl) ratingEl.value = String(Math.max(0, Math.min(5, Number(current.rating || 0) || 0)));
    if (favoriteEl) favoriteEl.checked = !!current.favorite;
    if (watchedEl) watchedEl.checked = !!current.watched;

    fillTechnicalMetaBox(v);

    metaEditor.hidden = false;
    window.setTimeout(() => titleEl?.focus(), 0);
  }

  function closeMetaEditor() {
    if (!metaEditor) return;
    metaEditor.hidden = true;
    metaEditVideo = null;
  }

  async function saveMetaEditor() {
    const v = metaEditVideo;
    if (!v || !v.path || !metaEditor) return;

    const titleEl = metaEditorEl("rsMetaTitle");
    const tagsEl = metaEditorEl("rsMetaTags");
    const notesEl = metaEditorEl("rsMetaNotes");
    const ratingEl = metaEditorEl("rsMetaRating");
    const favoriteEl = metaEditorEl("rsMetaFavorite");
    const watchedEl = metaEditorEl("rsMetaWatched");
    const saveBtn = metaEditorEl("rsMetaEditorSave");

    let rating = Number.parseInt(String(ratingEl?.value || "0"), 10);
    if (!Number.isFinite(rating)) rating = 0;
    rating = Math.max(0, Math.min(5, rating));

    try {
      if (saveBtn) saveBtn.disabled = true;
      setStatus(`Saving metadata for /${v.path}…`);

      const j = await apiJson(fileUserMetaSetUrl(), {
        method: "POST",
        headers: {
          "Accept": "application/json",
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          path: v.path,
          title: titleEl ? titleEl.value : "",
          tags_text: tagsEl ? tagsEl.value : "",
          notes: notesEl ? notesEl.value : "",
          rating,
          watched: watchedEl ? watchedEl.checked : false,
          favorite: favoriteEl ? favoriteEl.checked : false
        })
      });

      const merged = Object.assign({}, metaCache.get(v.path) || v.meta || {});
      merged.user = normalizeUserMeta(j.meta || {});
      merged.user_meta = merged.user;

      metaCache.set(v.path, merged);
      v.meta = merged;

      closeMetaEditor();
      updateMetaEls(v.path);
      render();
      setStatus(`Saved metadata for /${v.path}`);
    } catch (e) {
      setStatus(`Metadata save failed: ${e && e.message ? e.message : String(e)}`);
    } finally {
      if (saveBtn) saveBtn.disabled = false;
    }
  }

  async function editVideoMetadata(v) {
    if (!v || !v.path) return;
    setSelectedPath(v.path);

    try {
      await ensureVideoMeta(v);
      openMetaEditorFor(v);
    } catch (e) {
      setStatus(`Metadata load failed: ${e && e.message ? e.message : String(e)}`);
    }
  }



  function extractShareUrl(j) {
    if (!j || typeof j !== "object") return "";

    const direct = [
      j.url,
      j.share_url,
      j.public_url,
      j.full_url,
      j.link
    ].find(x => typeof x === "string" && x.trim());

    if (direct) return direct.trim();

    const share = j.share && typeof j.share === "object" ? j.share : null;
    if (share) {
      const nested = [
        share.url,
        share.share_url,
        share.public_url,
        share.full_url,
        share.link
      ].find(x => typeof x === "string" && x.trim());

      if (nested) return nested.trim();

      if (share.token) return `/s/${encodeURIComponent(String(share.token))}`;
    }

    if (j.token) return `/s/${encodeURIComponent(String(j.token))}`;
    return "";
  }

  async function copyTextToClipboard(text) {
    text = String(text || "");
    if (!text) return false;

    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(text);
        return true;
      }
    } catch (_) {}

    const ta = document.createElement("textarea");
    ta.value = text;
    ta.setAttribute("readonly", "");
    ta.style.position = "fixed";
    ta.style.left = "-9999px";
    ta.style.top = "0";
    document.body.appendChild(ta);
    ta.select();

    let ok = false;
    try { ok = document.execCommand("copy"); } catch (_) { ok = false; }
    ta.remove();
    return ok;
  }

  async function renameVideo(v) {
    if (!v || !v.path) return;

    const oldPath = String(v.path || "");
    const oldName = basename(oldPath);
    const nextNameRaw = prompt("Rename video", oldName);

    if (nextNameRaw === null) return;

    const nextName = String(nextNameRaw || "").trim();
    if (!nextName || nextName === oldName) return;

    if (nextName.includes("/") || nextName.includes("\\")) {
      setStatus("Rename failed: filename must not contain slashes.");
      return;
    }

    const parent = dirnameOf(oldPath);
    const nextPath = joinPath(parent, nextName);

    if (nextPath === oldPath) return;

    try {
      setStatus(`Renaming /${oldPath}…`);

      await apiJson(fileMoveUrl(oldPath, nextPath), { method: "POST" });

      const cached = metaCache.get(oldPath);
      if (cached) {
        metaCache.delete(oldPath);
        metaCache.set(nextPath, cached);
      }

      v.path = nextPath;
      v.name = nextName;

      setSelectedPath(nextPath);
      render();

      setStatus(`Renamed to /${nextPath}. Refreshing index…`);
      await scanVideos();
    } catch (e) {
      setStatus(`Rename failed: ${e && e.message ? e.message : String(e)}`);
    }
  }

  async function shareVideo(v) {
    if (!v || !v.path) return;

    try {
      setStatus(`Creating share link for /${v.path}…`);

      const j = await apiJson("/api/v4/shares/create", {
        method: "POST",
        headers: {
          "Accept": "application/json",
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          path: v.path,
          type: "file",
          expires_sec: 7 * 24 * 60 * 60
        })
      });

      const rawUrl = extractShareUrl(j);
      if (!rawUrl) {
        setStatus("Share created, but response did not include a link/token.");
        return;
      }

      const fullUrl = new URL(rawUrl, window.location.origin).toString();
      const copied = await copyTextToClipboard(fullUrl);

      setStatus(copied
        ? `Share link copied: ${fullUrl}`
        : `Share link created: ${fullUrl}`
      );
    } catch (e) {
      setStatus(`Share failed: ${e && e.message ? e.message : String(e)}`);
    }
  }

  async function deleteVideo(v) {
    if (!v || !v.path) return;

    if (!confirm(`Move this video to trash?\n\n/${v.path}`)) return;

    try {
      setStatus(`Deleting /${v.path}…`);
      await apiJson(fileDeleteUrl(v.path), { method: "POST" });
      allVideos = allVideos.filter(x => x.path !== v.path);
      setStatus(`Moved to trash: ${v.name}`);
      render();
    } catch (e) {
      setStatus(`Delete failed: ${e && e.message ? e.message : String(e)}`);
    }
  }


  function videoByPath(path) {
    path = String(path || "");
    return allVideos.find(v => v && v.path === path) || null;
  }

  window.PQNAS_REELSTACK_APP = {
    videoByPath,
    selectedVideo,
    selectPath: setSelectedPath,
    setStatus,
    openPlayer,
    editMetadata: editVideoMetadata,
    renameVideo,
    shareVideo,
    deleteVideo,
    downloadUrl: fileDownloadUrl,
    refreshIndex: scanVideos
  };

  window.dispatchEvent(new CustomEvent("pqnas-reelstack-ready", {
    detail: window.PQNAS_REELSTACK_APP
  }));

  loadIndex().catch((e) => {
    setStatus(`Could not load saved index: ${e && e.message ? e.message : String(e)}`);
    render();
  });

  scanBtn?.addEventListener("click", scanVideos);
  searchBtn?.addEventListener("click", openSearchModal);
  filterInput?.addEventListener("input", render);
  closePlayerBtn?.addEventListener("click", closePlayer);

  modal?.addEventListener("click", (ev) => {
    if (ev.target === modal) closePlayer();
  });

  document.addEventListener("keydown", handleReelStackKeydown, true);

  setStatus("Ready.");
  render();
})();
