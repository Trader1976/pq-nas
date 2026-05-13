(() => {
  "use strict";

  const API = "/api/v4/echostack";
  const VIEW_MODE_KEY = "echostack_view_mode_v1";
  const BOOKMARK_IMPORT_TAG = "imported-bookmark";
  const BOOKMARK_IMPORT_MAX_FILE_BYTES = 20 * 1024 * 1024;

  const el = (id) => document.getElementById(id);

  function loadViewMode() {
    try {
      const v = localStorage.getItem(VIEW_MODE_KEY);
      return v === "grid" ? "grid" : "list";
    } catch (_) {
      return "list";
    }
  }

  function saveViewMode(mode) {
    try {
      localStorage.setItem(VIEW_MODE_KEY, mode);
    } catch (_) {}
  }

  const state = {
    items: [],
    q: "",
    viewMode: loadViewMode(),
    selectedIndex: 0
  };

  let statusDotsTimer = null;

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
    versionEl.title = `Echo Stack ${ver}`;
    versionEl.hidden = false;
  }

  initAppVersion();

  function setStatus(msg, kind) {
    const s = el("status");
    if (!s) return;

    if (statusDotsTimer) {
      clearInterval(statusDotsTimer);
      statusDotsTimer = null;
    }

    const base = msg || "";
    s.className = "status" + (kind ? ` ${kind}` : "");

    if (kind === "working") {
      let dots = 0;
      s.textContent = base;
      statusDotsTimer = setInterval(() => {
        dots = (dots + 1) % 4;
        s.textContent = base + ".".repeat(dots);
      }, 360);
      return;
    }

    s.textContent = base;
  }


  function showEchoConfirm(options = {}) {
    const title = String(options.title || "Are you sure?");
    const message = String(options.message || "");
    const confirmText = String(options.confirmText || "OK");
    const cancelText = String(options.cancelText || "Cancel");
    const danger = Boolean(options.danger);

    return new Promise((resolve) => {
      const old = document.getElementById("echoConfirmBackdrop");
      if (old) old.remove();

      const backdrop = document.createElement("div");
      backdrop.id = "echoConfirmBackdrop";
      backdrop.className = "echoConfirmBackdrop";
      backdrop.setAttribute("role", "presentation");

      const dialog = document.createElement("div");
      dialog.className = "echoConfirmDialog";
      dialog.setAttribute("role", "dialog");
      dialog.setAttribute("aria-modal", "true");
      dialog.setAttribute("aria-labelledby", "echoConfirmTitle");

      const head = document.createElement("div");
      head.className = "echoConfirmHead";

      const icon = document.createElement("div");
      icon.className = danger ? "echoConfirmIcon danger" : "echoConfirmIcon";
      icon.textContent = danger ? "!" : "?";

      const titleEl = document.createElement("div");
      titleEl.id = "echoConfirmTitle";
      titleEl.className = "echoConfirmTitle";
      titleEl.textContent = title;

      head.appendChild(icon);
      head.appendChild(titleEl);

      const body = document.createElement("div");
      body.className = "echoConfirmBody";
      body.textContent = message;

      const actions = document.createElement("div");
      actions.className = "echoConfirmActions";

      const cancel = document.createElement("button");
      cancel.type = "button";
      cancel.className = "echoConfirmCancel";
      cancel.textContent = cancelText;

      const ok = document.createElement("button");
      ok.type = "button";
      ok.className = danger ? "echoConfirmOk danger" : "echoConfirmOk";
      ok.textContent = confirmText;

      actions.appendChild(cancel);
      actions.appendChild(ok);

      dialog.appendChild(head);
      if (message) dialog.appendChild(body);
      dialog.appendChild(actions);
      backdrop.appendChild(dialog);
      document.body.appendChild(backdrop);

      let done = false;

      const finish = (value) => {
        if (done) return;
        done = true;
        document.removeEventListener("keydown", onKey, true);
        backdrop.remove();
        resolve(Boolean(value));
      };

      const onKey = (e) => {
        if (e.key === "Escape") {
          e.preventDefault();
          finish(false);
          return;
        }

        if (e.key === "Enter") {
          e.preventDefault();
          finish(true);
        }
      };

      cancel.addEventListener("click", () => finish(false));
      ok.addEventListener("click", () => finish(true));

      backdrop.addEventListener("mousedown", (e) => {
        if (e.target === backdrop) finish(false);
      });

      document.addEventListener("keydown", onKey, true);

      setTimeout(() => {
        if (danger) {
          cancel.focus();
        } else {
          ok.focus();
        }
      }, 0);
    });
  }

  async function api(path, opts = {}) {
    const r = await fetch(API + path, {
      credentials: "include",
      cache: "no-store",
      headers: {
        "Accept": "application/json",
        ...(opts.body ? { "Content-Type": "application/json" } : {})
      },
      ...opts
    });

    const j = await r.json().catch(() => ({}));
    if (!r.ok || !j.ok) {
      const reason = j.archive_error || j.error || j.message || `HTTP ${r.status}`;
      const detail = j.message && j.message !== reason ? `${reason}: ${j.message}` : reason;
      throw new Error(detail);
    }
    return j;
  }

  function fmtTime(epoch) {
    const n = Number(epoch || 0);
    if (!n) return "";
    try {
      return new Date(n * 1000).toLocaleString();
    } catch {
      return "";
    }
  }

  function fmtBytes(n) {
    const bytes = Number(n || 0);
    if (!Number.isFinite(bytes) || bytes <= 0) return "";

    const units = ["B", "KB", "MB", "GB", "TB"];
    let value = bytes;
    let unit = 0;

    while (value >= 1024 && unit < units.length - 1) {
      value /= 1024;
      unit++;
    }

    if (unit === 0) return `${bytes} B`;
    return `${value.toFixed(value >= 10 ? 1 : 2)} ${units[unit]}`;
  }


  function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  function cleanBookmarkText(value) {
    return String(value || "")
      .replace(/\s+/g, " ")
      .trim()
      .slice(0, 240);
  }

  function normalizeImportUrl(value) {
    const raw = String(value || "").trim();
    if (!raw) return "";

    try {
      const u = new URL(raw);
      if (u.protocol !== "http:" && u.protocol !== "https:") return "";
      return u.toString();
    } catch (_) {
      return "";
    }
  }

  function directChildByTag(parent, tagName) {
    const wanted = String(tagName || "").toUpperCase();
    for (const child of Array.from(parent?.children || [])) {
      if (child.tagName === wanted) return child;
    }
    return null;
  }

  function parseBookmarkHtmlImport(htmlText) {
    const html = String(htmlText || "");

    if (!/NETSCAPE-Bookmark-file-1/i.test(html) && !/<a\s+[^>]*href\s*=/i.test(html)) {
      throw new Error("This does not look like a browser bookmarks HTML export.");
    }

    const doc = new DOMParser().parseFromString(html, "text/html");
    const root = doc.querySelector("dl");

    if (!root) {
      throw new Error("No bookmark list found in this file.");
    }

    const bookmarks = [];
    const seenInFile = new Set();

    function addAnchor(anchor, folders) {
      const url = normalizeImportUrl(anchor.getAttribute("href") || "");
      if (!url || seenInFile.has(url)) return;

      seenInFile.add(url);

      const title = cleanBookmarkText(anchor.textContent) || url;
      const collection = folders.filter(Boolean).join(" / ") || "Imported bookmarks";
      const addDateRaw = String(anchor.getAttribute("ADD_DATE") || "").trim();
      const addedEpoch = /^\d+$/.test(addDateRaw) ? Number(addDateRaw) : 0;

      bookmarks.push({
        url,
        title,
        collection: collection.slice(0, 180),
        added_epoch: Number.isFinite(addedEpoch) ? addedEpoch : 0
      });
    }

    function walkDl(dl, folders) {
      const children = Array.from(dl.children || []);

      for (let i = 0; i < children.length; i++) {
        const node = children[i];
        if (!node || node.tagName === "P") continue;

        if (node.tagName === "DT") {
          const anchor = directChildByTag(node, "A");
          const folder = directChildByTag(node, "H3");

          if (anchor) {
            addAnchor(anchor, folders);
            continue;
          }

          if (folder) {
            const name = cleanBookmarkText(folder.textContent);
            let subDl = directChildByTag(node, "DL");

            if (!subDl) {
              for (let j = i + 1; j < children.length; j++) {
                if (children[j].tagName === "DL") {
                  subDl = children[j];
                  i = j;
                  break;
                }
                if (children[j].tagName === "DT") break;
              }
            }

            if (subDl) {
              walkDl(subDl, name ? folders.concat(name) : folders);
            }
            continue;
          }

          const nestedAnchor = node.querySelector("a[href]");
          if (nestedAnchor) addAnchor(nestedAnchor, folders);
          continue;
        }

        if (node.tagName === "A") {
          addAnchor(node, folders);
          continue;
        }

        if (node.tagName === "H3") {
          const name = cleanBookmarkText(node.textContent);
          let subDl = null;

          for (let j = i + 1; j < children.length; j++) {
            if (children[j].tagName === "DL") {
              subDl = children[j];
              i = j;
              break;
            }
            if (children[j].tagName === "DT") break;
          }

          if (subDl) {
            walkDl(subDl, name ? folders.concat(name) : folders);
          }
          continue;
        }

        if (node.tagName === "DL") {
          walkDl(node, folders);
        }
      }
    }

    walkDl(root, []);
    return bookmarks;
  }


  function bookmarkHtmlEscape(value) {
    return String(value || "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function bookmarkExportUrl(value) {
    const raw = String(value || "").trim();
    if (!raw) return "";

    try {
      const u = new URL(raw);
      if (u.protocol !== "http:" && u.protocol !== "https:") return "";
      return u.toString();
    } catch (_) {
      return "";
    }
  }

  function bookmarkExportTitle(item) {
    return cleanBookmarkText(item.title || item.url || "Untitled") || "Untitled";
  }

  function bookmarkExportFolderPath(item) {
    const raw = cleanBookmarkText(item.collection || "");
    if (!raw) return ["Echo Stack"];

    const parts = raw
      .split(/\s+\/\s+/)
      .map((part) => cleanBookmarkText(part))
      .filter(Boolean);

    return parts.length ? parts : ["Echo Stack"];
  }

  function makeBookmarkTree(items) {
    const root = {
      folders: new Map(),
      bookmarks: []
    };

    function folderForPath(pathParts) {
      let cur = root;

      for (const part of pathParts) {
        if (!cur.folders.has(part)) {
          cur.folders.set(part, {
            folders: new Map(),
            bookmarks: []
          });
        }

        cur = cur.folders.get(part);
      }

      return cur;
    }

    const seen = new Set();

    for (const item of items || []) {
      const url = bookmarkExportUrl(item.url || "");
      if (!url || seen.has(url)) continue;
      seen.add(url);

      const folder = folderForPath(bookmarkExportFolderPath(item));
      const epoch = Number(item.created_epoch || item.updated_epoch || 0);

      folder.bookmarks.push({
        url,
        title: bookmarkExportTitle(item),
        addDate: Number.isFinite(epoch) && epoch > 0 ? Math.floor(epoch) : Math.floor(Date.now() / 1000)
      });
    }

    return root;
  }

  function serializeBookmarkFolder(name, folder, depth) {
    const pad = "    ".repeat(depth);
    const childPad = "    ".repeat(depth + 1);
    const now = Math.floor(Date.now() / 1000);
    const lines = [];

    if (name) {
      lines.push(`${pad}<DT><H3 ADD_DATE="${now}" LAST_MODIFIED="${now}">${bookmarkHtmlEscape(name)}</H3>`);
      lines.push(`${pad}<DL><p>`);
    }

    for (const bookmark of folder.bookmarks) {
      lines.push(
        `${childPad}<DT><A HREF="${bookmarkHtmlEscape(bookmark.url)}" ADD_DATE="${bookmark.addDate}">${bookmarkHtmlEscape(bookmark.title)}</A>`
      );
    }

    const folderNames = Array.from(folder.folders.keys()).sort((a, b) => a.localeCompare(b));
    for (const folderName of folderNames) {
      lines.push(serializeBookmarkFolder(folderName, folder.folders.get(folderName), depth + 1));
    }

    if (name) {
      lines.push(`${pad}</DL><p>`);
    }

    return lines.join("\n");
  }

  function exportBookmarksHtml(items) {
    const tree = makeBookmarkTree(items);
    const now = Math.floor(Date.now() / 1000);

    const lines = [
      "<!DOCTYPE NETSCAPE-Bookmark-file-1>",
      "<!-- This is an automatically generated file.",
      "     It can be imported into Chrome, Brave, Edge, Firefox, and other browsers.",
      "     Exported by DNA-Nexus Echo Stack.",
      "     DO NOT EDIT! -->",
      '<META HTTP-EQUIV="Content-Type" CONTENT="text/html; charset=UTF-8">',
      "<TITLE>Echo Stack Bookmarks</TITLE>",
      "<H1>Echo Stack Bookmarks</H1>",
      "<DL><p>"
    ];

    for (const bookmark of tree.bookmarks) {
      lines.push(
        `    <DT><A HREF="${bookmarkHtmlEscape(bookmark.url)}" ADD_DATE="${bookmark.addDate}">${bookmarkHtmlEscape(bookmark.title)}</A>`
      );
    }

    const folderNames = Array.from(tree.folders.keys()).sort((a, b) => a.localeCompare(b));
    for (const folderName of folderNames) {
      lines.push(serializeBookmarkFolder(folderName, tree.folders.get(folderName), 1));
    }

    lines.push("</DL><p>");
    return lines.join("\n") + "\n";
  }

  function downloadTextFile(filename, text, mime) {
    const blob = new Blob([text], { type: mime || "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);

    try {
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      a.rel = "noopener";
      document.body.appendChild(a);
      a.click();
      a.remove();
    } finally {
      setTimeout(() => URL.revokeObjectURL(url), 1500);
    }
  }

  function todayIsoDate() {
    try {
      return new Date().toISOString().slice(0, 10);
    } catch (_) {
      return "export";
    }
  }

  async function exportBookmarksToHtmlFile() {
    const btn = el("exportBookmarksBtn");

    if (btn) {
      btn.disabled = true;
      btn.classList.add("exporting");
      btn.textContent = "Exporting";
    }

    try {
      setStatus("Preparing bookmark export…", "working");

      const j = await api("/items?limit=500");
      const items = Array.isArray(j.items) ? j.items : [];

      if (!items.length) {
        setStatus("No links to export.", "bad");
        return;
      }

      const html = exportBookmarksHtml(items);
      const count = makeBookmarkTree(items).folders.size + items.length;
      const filename = `echo-stack-bookmarks-${todayIsoDate()}.html`;

      downloadTextFile(filename, html, "text/html;charset=utf-8");

      const exportedLinks = (items || []).filter((item) => bookmarkExportUrl(item.url || "")).length;
      setStatus(`Exported ${exportedLinks} bookmarks to ${filename}.`, "good");
    } finally {
      if (btn) {
        btn.disabled = false;
        btn.classList.remove("exporting");
        btn.textContent = "Export bookmarks";
      }
    }
  }

  function buildImportedBookmarkPayload(bookmark) {
    return {
      url: bookmark.url,
      final_url: "",
      title: bookmark.title || bookmark.url,
      description: "",
      site_name: "",
      favicon_url: faviconFromUrl(bookmark.url),
      preview_image_url: "",
      collection: bookmark.collection || "Imported bookmarks",
      tags_text: BOOKMARK_IMPORT_TAG,
      notes: "",
      read_state: "unread"
    };
  }

  async function importBookmarksFromText(htmlText, filename) {
    const parsed = parseBookmarkHtmlImport(htmlText);

    if (!parsed.length) {
      throw new Error("No HTTP/HTTPS bookmarks found in this file.");
    }

    const folderCount = new Set(parsed.map((b) => b.collection || "Imported bookmarks")).size;

    let existingItems = [];
    try {
      const j = await api("/items?limit=500");
      existingItems = Array.isArray(j.items) ? j.items : [];
    } catch (_) {
      existingItems = Array.isArray(state.items) ? state.items : [];
    }

    const existingUrls = new Set(
      existingItems
        .map((item) => normalizeImportUrl(item.url || ""))
        .filter(Boolean)
    );

    const toImport = parsed.filter((bookmark) => !existingUrls.has(bookmark.url));
    const skippedExisting = parsed.length - toImport.length;

    if (!toImport.length) {
      setStatus(`Bookmark import found ${parsed.length} links, but all already exist.`, "good");
      return;
    }

    const ok = await showEchoConfirm({
      title: "Import bookmarks?",
      message:
        `File: ${filename || "selected file"}\n\n` +
        `Found: ${parsed.length} bookmarks in ${folderCount} folder/collection groups\n` +
        `Will import: ${toImport.length}\n` +
        `Will skip existing: ${skippedExisting}\n\n` +
        `Imported links will get tag "${BOOKMARK_IMPORT_TAG}".`,
      confirmText: "Import",
      cancelText: "Cancel"
    });

    if (!ok) {
      setStatus("Bookmark import cancelled.");
      return;
    }

    const importBtn = el("importBookmarksBtn");
    if (importBtn) {
      importBtn.disabled = true;
      importBtn.classList.add("importing");
      importBtn.textContent = "Importing";
    }

    let imported = 0;
    let failed = 0;

    try {
      for (let i = 0; i < toImport.length; i++) {
        const bookmark = toImport[i];

        setStatus(`Importing bookmarks ${i + 1}/${toImport.length}`, "working");

        try {
          await api("/items/create", {
            method: "POST",
            body: JSON.stringify(buildImportedBookmarkPayload(bookmark))
          });

          imported++;
          existingUrls.add(bookmark.url);
        } catch (err) {
          failed++;
          console.warn("Echo Stack bookmark import failed:", bookmark.url, err);
        }

        if ((i + 1) % 10 === 0) {
          await sleep(80);
        }
      }
    } finally {
      if (importBtn) {
        importBtn.disabled = false;
        importBtn.classList.remove("importing");
        importBtn.textContent = "Import bookmarks";
      }
    }

    state.q = "";
    const search = el("searchInput");
    if (search) search.value = "";

    const failedText = failed ? `, ${failed} failed` : "";
    setStatus(
      `Bookmark import finished: ${imported} imported, ${skippedExisting} skipped as existing${failedText}.`,
      failed ? "bad" : "good"
    );

    await loadItems();
  }

  async function handleBookmarkImportFile(file) {
    if (!file) return;

    if (file.size > BOOKMARK_IMPORT_MAX_FILE_BYTES) {
      throw new Error("Bookmark file is too large for browser-side import.");
    }

    setStatus("Reading bookmark file…", "working");
    const text = await file.text();
    await importBookmarksFromText(text, file.name || "bookmarks.html");
  }

  function faviconFromUrl(url) {
    try {
      const u = new URL(url);
      return `${u.origin}/favicon.ico`;
    } catch {
      return "";
    }
  }


  function pluralLocal(count, one, many) {
    return Number(count) === 1 ? one : many;
  }

  function updateResultCount() {
    const out = el("resultCount");
    if (!out) return;

    const count = Array.isArray(state.items) ? state.items.length : 0;
    const q = String(state.q || "").trim();

    if (q) {
      out.textContent = `${count} ${pluralLocal(count, "result", "results")}`;
      out.title = `${count} ${pluralLocal(count, "result", "results")} for “${q}”`;
      return;
    }

    out.textContent = `${count} ${pluralLocal(count, "link", "links")}`;
    out.title = `${count} ${pluralLocal(count, "saved link", "saved links")}`;
  }

  function metaLine(item) {
    const parts = [];

    if (item.site_name) parts.push(item.site_name);
    if (item.collection) parts.push(`Collection: ${item.collection}`);
    if (item.tags_text) parts.push(`Tags: ${item.tags_text}`);
    if (item.favorite) parts.push("Favorite");

    const archive = item.archive_status || "none";
    if (archive === "none") {
      parts.push("Saved link");
    } else if (archive === "failed" && item.archive_error) {
      parts.push(`Archive: failed — ${item.archive_error}`);
    } else {
      parts.push(`Archive: ${archive}`);
    }

    const archiveBytes = fmtBytes(item.archive_bytes);
    if (archiveBytes) parts.push(archiveBytes);

    const t = fmtTime(item.created_epoch);
    if (t) parts.push(t);

    return parts.join(" • ");
  }

  async function loadItems() {
    const q = state.q ? `?q=${encodeURIComponent(state.q)}` : "";
    const j = await api(`/items${q}`);
    state.items = Array.isArray(j.items) ? j.items : [];
    clampSelectedIndex();
    render();
  }


  function clampSelectedIndex() {
    const max = Math.max(0, state.items.length - 1);
    if (!Number.isFinite(state.selectedIndex)) state.selectedIndex = 0;
    if (state.selectedIndex < 0) state.selectedIndex = 0;
    if (state.selectedIndex > max) state.selectedIndex = max;
  }

  function itemCards() {
    return Array.from(document.querySelectorAll("#items .item"));
  }

  function selectedCard() {
    const cards = itemCards();
    clampSelectedIndex();
    return cards[state.selectedIndex] || null;
  }

  function setSelectedIndex(index, options = {}) {
    if (!state.items.length) {
      state.selectedIndex = 0;
      return;
    }

    const max = state.items.length - 1;
    state.selectedIndex = Math.max(0, Math.min(max, Number(index) || 0));

    const cards = itemCards();
    cards.forEach((card, i) => {
      const selected = i === state.selectedIndex;
      card.classList.toggle("selected", selected);
      card.setAttribute("aria-selected", selected ? "true" : "false");
      card.tabIndex = selected ? 0 : -1;
    });

    const card = cards[state.selectedIndex];
    if (card && options.scroll !== false) {
      card.scrollIntoView({ block: "nearest", inline: "nearest" });
    }
  }

  function gridColumnCount() {
    const root = el("items");
    const cards = itemCards();

    if (!root || cards.length < 2 || state.viewMode !== "grid") return 1;

    const firstTop = Math.round(cards[0].getBoundingClientRect().top);
    let cols = 0;

    for (const card of cards) {
      const top = Math.round(card.getBoundingClientRect().top);
      if (Math.abs(top - firstTop) <= 3) cols++;
      else break;
    }

    return Math.max(1, cols);
  }

  function moveSelectionByKey(key) {
    if (!state.items.length) return;

    const cols = gridColumnCount();
    let next = state.selectedIndex;

    if (key === "ArrowLeft") next -= 1;
    else if (key === "ArrowRight") next += 1;
    else if (key === "ArrowUp") next -= cols;
    else if (key === "ArrowDown") next += cols;
    else return;

    setSelectedIndex(next);
  }

  function toggleSelectedEditPanel() {
    const card = selectedCard();
    if (!card) return;

    const item = state.items[state.selectedIndex];
    if (!item) return;

    const notes = card.querySelector(".itemNotes");
    openInlineEditor(item, card, notes, { focus: false });
  }

  function closeSelectedEditPanel() {
    const card = selectedCard();
    if (!card) return;

    const panel = card.querySelector(".itemEditPanel");
    if (panel) panel.remove();
  }

  function isTypingTarget(target) {
    if (!target) return false;
    const tag = String(target.tagName || "").toUpperCase();
    return tag === "INPUT" ||
           tag === "TEXTAREA" ||
           tag === "SELECT" ||
           tag === "BUTTON" ||
           target.isContentEditable;
  }

  function bindKeyboardNavigation() {
    if (bindKeyboardNavigation.bound) return;
    bindKeyboardNavigation.bound = true;

    document.addEventListener("keydown", (e) => {
      if (e.defaultPrevented || e.altKey || e.ctrlKey || e.metaKey) return;

      if (isTypingTarget(e.target)) return;

      if (e.key === "ArrowLeft" ||
          e.key === "ArrowRight" ||
          e.key === "ArrowUp" ||
          e.key === "ArrowDown") {
        e.preventDefault();
        moveSelectionByKey(e.key);
        return;
      }

      if (e.key === " " || e.code === "Space") {
        e.preventDefault();
        toggleSelectedEditPanel();
        return;
      }

      if (e.key === "Escape") {
        e.preventDefault();
        closeSelectedEditPanel();
      }
    });
  }


  function ensureItemContextMenu() {
    let menu = document.getElementById("echoItemContextMenu");
    if (menu) return menu;

    menu = document.createElement("div");
    menu.id = "echoItemContextMenu";
    menu.className = "itemContextMenu";
    menu.hidden = true;
    menu.setAttribute("role", "menu");
    document.body.appendChild(menu);

    return menu;
  }

  function closeItemContextMenu() {
    const menu = document.getElementById("echoItemContextMenu");
    if (!menu) return;

    menu.hidden = true;
    menu.innerHTML = "";
    menu.classList.remove("open");
  }

  function contextMenuButton(label, action, options = {}) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.textContent = label;
    btn.setAttribute("role", "menuitem");

    if (options.danger) {
      btn.classList.add("danger");
    }

    if (options.disabled) {
      btn.disabled = true;
    }

    btn.addEventListener("click", async () => {
      closeItemContextMenu();

      if (options.disabled) return;

      try {
        await action();
      } catch (err) {
        setStatus(err.message || String(err), "bad");
      }
    });

    return btn;
  }

  async function copyTextToClipboard(text) {
    const value = String(text || "");

    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(value);
      return;
    }

    const area = document.createElement("textarea");
    area.value = value;
    area.style.position = "fixed";
    area.style.left = "-9999px";
    area.style.top = "0";
    document.body.appendChild(area);
    area.focus();
    area.select();

    try {
      document.execCommand("copy");
    } finally {
      area.remove();
    }
  }

  function positionItemContextMenu(menu, x, y) {
    menu.style.left = "0px";
    menu.style.top = "0px";
    menu.hidden = false;
    menu.classList.add("open");

    const rect = menu.getBoundingClientRect();
    const pad = 10;
    const left = Math.max(pad, Math.min(x, window.innerWidth - rect.width - pad));
    const top = Math.max(pad, Math.min(y, window.innerHeight - rect.height - pad));

    menu.style.left = `${left}px`;
    menu.style.top = `${top}px`;
  }

  function openItemContextMenu(x, y, item, node) {
    const menu = ensureItemContextMenu();
    const archiveStatus = item.archive_status || "none";
    const hasUrl = Boolean(item.url);
    const isArchived = archiveStatus === "archived";
    const isArchiving = archiveStatus === "archiving";

    menu.innerHTML = "";

    menu.appendChild(contextMenuButton("Open link", () => {
      if (item.url) {
        window.open(item.url, "_blank", "noopener,noreferrer");
      }
    }, { disabled: !hasUrl }));

    if (isArchived) {
      menu.appendChild(contextMenuButton("Open archive", () => {
        window.open(`${API}/archive/view?id=${encodeURIComponent(item.id)}`, "_blank", "noopener,noreferrer");
      }));
    }

    menu.appendChild(document.createElement("hr"));

    menu.appendChild(contextMenuButton("Edit", () => {
      const notes = node.querySelector(".itemNotes");
      openInlineEditor(item, node, notes);
    }));

    menu.appendChild(contextMenuButton(
      item.read_state === "read" ? "Mark unread" : "Mark read",
      () => updateItem(item.id, {
        read_state: item.read_state === "read" ? "unread" : "read"
      })
    ));

    menu.appendChild(contextMenuButton(
      item.favorite ? "Remove favorite" : "Add favorite",
      () => updateItem(item.id, { favorite: !item.favorite })
    ));

    menu.appendChild(contextMenuButton("Copy URL", async () => {
      await copyTextToClipboard(item.url || "");
      setStatus("URL copied.", "good");
    }, { disabled: !hasUrl }));

    menu.appendChild(document.createElement("hr"));

    if (isArchiving) {
      menu.appendChild(contextMenuButton("Archiving…", () => {}, { disabled: true }));
    } else if (!isArchived) {
      menu.appendChild(contextMenuButton(
        archiveStatus === "failed" ? "Retry archive" : "Archive",
        () => archiveItem(item.id)
      ));
    }

    menu.appendChild(contextMenuButton("Delete", async () => {
      const ok = await showEchoConfirm({
        title: "Delete Echo Stack item?",
        message: "This removes the saved link from Echo Stack. The original website is not affected.",
        confirmText: "Delete",
        cancelText: "Cancel",
        danger: true
      });
      if (!ok) return;
      await deleteItem(item.id);
    }, { danger: true }));

    positionItemContextMenu(menu, x, y);
  }

  function bindItemContextMenuDismiss() {
    if (bindItemContextMenuDismiss.bound) return;
    bindItemContextMenuDismiss.bound = true;

    document.addEventListener("click", (e) => {
      const menu = document.getElementById("echoItemContextMenu");
      if (!menu || menu.hidden) return;
      if (e.target && e.target.closest("#echoItemContextMenu")) return;
      closeItemContextMenu();
    }, true);

    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape") {
        closeItemContextMenu();
      }
    });

    window.addEventListener("resize", closeItemContextMenu);
    window.addEventListener("scroll", closeItemContextMenu, true);
  }

  function render() {
    const root = el("items");
    const tpl = el("itemTemplate");
    if (!root || !tpl) return;

    root.className = `items ${state.viewMode === "grid" ? "gridMode" : "listMode"}`;
    updateViewModeButton();
    updateResultCount();

    root.innerHTML = "";

    if (!state.items.length) {
      const empty = document.createElement("div");
      empty.className = "empty";
      empty.textContent = "No links saved yet. Paste a URL above to start your stack.";
      root.appendChild(empty);
      return;
    }

    for (const item of state.items) {
      const node = tpl.content.firstElementChild.cloneNode(true);
      const itemIndex = root.children.length;

      node.dataset.index = String(itemIndex);
      node.tabIndex = itemIndex === state.selectedIndex ? 0 : -1;
      node.setAttribute("role", "option");
      node.setAttribute("aria-selected", itemIndex === state.selectedIndex ? "true" : "false");
      node.classList.toggle("selected", itemIndex === state.selectedIndex);

      node.addEventListener("click", (e) => {
        if (e.target && e.target.closest("button, input, textarea, a, select")) return;
        setSelectedIndex(itemIndex, { scroll: false });
      });

      node.addEventListener("contextmenu", (e) => {
        if (e.target && e.target.closest("input, textarea, select")) return;

        e.preventDefault();
        setSelectedIndex(itemIndex, { scroll: false });
        openItemContextMenu(e.clientX, e.clientY, item, node);
      });

      const title = node.querySelector(".itemTitle");
      const url = node.querySelector(".itemUrl");
      const meta = node.querySelector(".itemMeta");
      const notes = node.querySelector(".itemNotes");
      const favBtn = node.querySelector(".favBtn");
      const readBtn = node.querySelector(".readBtn");
      const saveBtn = node.querySelector(".saveItemBtn");
      const deleteBtn = node.querySelector(".deleteBtn");
      const archiveStatus = item.archive_status || "none";

      const editBtn = document.createElement("button");
      editBtn.type = "button";
      editBtn.className = "editBtn";
      editBtn.textContent = "Edit";
      node.querySelector(".itemActions").insertBefore(editBtn, favBtn);

      const head = document.createElement("div");
      head.className = "itemHead";

      const fav = document.createElement("img");
      fav.className = "favicon";
      fav.alt = "";
      fav.loading = "lazy";
      fav.referrerPolicy = "no-referrer";
      const favSrc = item.favicon_url || "";
      if (favSrc) {
        fav.src = favSrc;
      } else {
        fav.style.display = "none";
      }

      fav.onerror = () => {
        fav.style.display = "none";
      };

      const titleWrap = document.createElement("div");
      titleWrap.className = "itemTitleWrap";

      title.textContent = item.title || item.url || "Untitled";

      const stateBadge = document.createElement("span");
      stateBadge.className = `readBadge ${item.read_state === "read" ? "read" : "unread"}`;
      stateBadge.textContent = item.read_state === "read" ? "Read" : "Unread";

      titleWrap.appendChild(title);
      titleWrap.appendChild(stateBadge);
      head.appendChild(fav);
      head.appendChild(titleWrap);

      node.querySelector(".itemMain").prepend(head);

      url.href = item.url || "#";
      url.textContent = item.url || "";

      if (item.description) {
        const desc = document.createElement("div");
        desc.className = "itemDescription";
        desc.textContent = item.description;
        url.insertAdjacentElement("afterend", desc);
      }

      if (item.preview_image_url) {
        const previewWrap = document.createElement("a");
        previewWrap.className = "itemPreview";
        previewWrap.href = item.url || item.preview_image_url;
        previewWrap.target = "_blank";
        previewWrap.rel = "noopener noreferrer";

        const previewImg = document.createElement("img");
        previewImg.alt = "";
        previewImg.loading = "lazy";
        previewImg.referrerPolicy = "no-referrer";
        previewImg.src = item.preview_image_url;
        previewImg.onerror = () => {
          previewWrap.remove();
        };

        previewWrap.appendChild(previewImg);

        const descEl = node.querySelector(".itemDescription");
        if (descEl) {
          descEl.insertAdjacentElement("afterend", previewWrap);
        } else {
          url.insertAdjacentElement("afterend", previewWrap);
        }
      }

      meta.textContent = metaLine(item);
      notes.value = item.notes || "";

      favBtn.textContent = item.favorite ? "★ Favorite" : "☆ Favorite";
      readBtn.textContent = item.read_state === "read" ? "Mark unread" : "Mark read";

      editBtn.addEventListener("click", () => {
        openInlineEditor(item, node, notes);
      });

      favBtn.addEventListener("click", async () => {
        await updateItem(item.id, { favorite: !item.favorite });
      });

      readBtn.addEventListener("click", async () => {
        await updateItem(item.id, {
          read_state: item.read_state === "read" ? "unread" : "read"
        });
      });

      if (archiveStatus === "archived") {
        const openArchiveBtn = document.createElement("button");
        openArchiveBtn.type = "button";
        openArchiveBtn.className = "archiveAction archived";
        openArchiveBtn.textContent = "Open archive";
        openArchiveBtn.addEventListener("click", () => {
          window.open(`${API}/archive/view?id=${encodeURIComponent(item.id)}`, "_blank", "noopener,noreferrer");
        });
        node.querySelector(".itemActions").insertBefore(openArchiveBtn, saveBtn);
      } else if (archiveStatus === "archiving") {
        const archivingBtn = document.createElement("button");
        archivingBtn.type = "button";
        archivingBtn.className = "archiveAction archiving";
        archivingBtn.textContent = "Archiving";
        archivingBtn.disabled = true;
        node.querySelector(".itemActions").insertBefore(archivingBtn, saveBtn);
      } else {
        const archiveBtn = document.createElement("button");
        archiveBtn.type = "button";
        archiveBtn.className = "archiveAction ready";
        archiveBtn.textContent = archiveStatus === "failed" ? "Retry archive" : "Archive";
        archiveBtn.addEventListener("click", () => {
          archiveItem(item.id, archiveBtn);
        });
        node.querySelector(".itemActions").insertBefore(archiveBtn, saveBtn);
      }
      saveBtn.addEventListener("click", async () => {
        await updateItem(item.id, { notes: notes.value || "" });
      });

      deleteBtn.addEventListener("click", async () => {
        const ok = await showEchoConfirm({
          title: "Delete Echo Stack item?",
          message: "This removes the saved link from Echo Stack. The original website is not affected.",
          confirmText: "Delete",
          cancelText: "Cancel",
          danger: true
        });
        if (!ok) return;
        await deleteItem(item.id);
      });

      root.appendChild(node);
    }

    clampSelectedIndex();
    setSelectedIndex(state.selectedIndex, { scroll: false });
  }


  function makeEditInput(labelText, value, options = {}) {
    const wrap = document.createElement("label");
    wrap.className = "editField";

    const label = document.createElement("span");
    label.textContent = labelText;

    const input = options.textarea ? document.createElement("textarea") : document.createElement("input");
    input.value = value || "";

    if (!options.textarea) {
      input.type = options.type || "text";
    }

    if (options.placeholder) {
      input.placeholder = options.placeholder;
    }

    wrap.appendChild(label);
    wrap.appendChild(input);

    return { wrap, input };
  }

  function openInlineEditor(item, node, notesEl, options = {}) {
    const oldPanel = node.querySelector(".itemEditPanel");
    if (oldPanel) {
      oldPanel.remove();
      return;
    }

    const main = node.querySelector(".itemMain");
    if (!main) return;

    const panel = document.createElement("div");
    panel.className = "itemEditPanel";

    const urlField = makeEditInput("URL", item.url || "", {
      type: "url",
      placeholder: "https://example.com/article"
    });
    const titleField = makeEditInput("Title", item.title || "", {
      placeholder: "Title"
    });
    const collectionField = makeEditInput("Collection", item.collection || "", {
      placeholder: "Collection / Folder"
    });
    const tagsField = makeEditInput("Tags", item.tags_text || "", {
      placeholder: "tag1, tag2"
    });
    const notesField = makeEditInput("Notes", notesEl?.value || item.notes || "", {
      textarea: true,
      placeholder: "Notes"
    });

    const grid = document.createElement("div");
    grid.className = "itemEditGrid";
    grid.appendChild(urlField.wrap);
    grid.appendChild(titleField.wrap);
    grid.appendChild(collectionField.wrap);
    grid.appendChild(tagsField.wrap);

    const actions = document.createElement("div");
    actions.className = "itemEditActions";

    const save = document.createElement("button");
    save.type = "button";
    save.textContent = "Save edit";

    const cancel = document.createElement("button");
    cancel.type = "button";
    cancel.textContent = "Cancel";

    actions.appendChild(save);
    actions.appendChild(cancel);

    panel.appendChild(grid);
    panel.appendChild(notesField.wrap);
    panel.appendChild(actions);

    main.appendChild(panel);

    if (options.focus !== false) {
      urlField.input.focus();
    }

    const submitEdit = async () => {
      if (save.disabled) return;

      const url = String(urlField.input.value || "").trim();
      if (!url) {
        setStatus("URL cannot be empty.", "bad");
        urlField.input.focus();
        return;
      }

      save.disabled = true;
      save.textContent = "Saving…";

      try {
        await updateItem(item.id, {
          url,
          title: String(titleField.input.value || "").trim() || url,
          collection: String(collectionField.input.value || "").trim(),
          tags_text: String(tagsField.input.value || "").trim(),
          notes: String(notesField.input.value || "").trim()
        });
      } catch (err) {
        save.disabled = false;
        save.textContent = "Save edit";
        setStatus(err.message || String(err), "bad");
      }
    };

    const handleEditKeydown = (e) => {
      if (e.key !== "Enter" || e.isComposing) return;

      // Notes still allows multiline text with Shift+Enter.
      if (e.target && e.target.tagName === "TEXTAREA" && e.shiftKey) return;

      e.preventDefault();
      submitEdit();
    };

    for (const input of [
      urlField.input,
      titleField.input,
      collectionField.input,
      tagsField.input,
      notesField.input
    ]) {
      input.addEventListener("keydown", handleEditKeydown);
    }

    cancel.addEventListener("click", () => {
      panel.remove();
    });

    save.addEventListener("click", () => {
      submitEdit();
    });
  }

  async function saveNewItem() {
    const url = (el("urlInput")?.value || "").trim();
    const title = (el("titleInput")?.value || "").trim();
    const collection = (el("collectionInput")?.value || "").trim();
    const tags = (el("tagsInput")?.value || "").trim();
    const notes = (el("notesInput")?.value || "").trim();

    if (!url) {
      setStatus("Paste a URL first.", "bad");
      return;
    }

    setStatus("Fetching preview…");

    let preview = {};
    try {
      preview = await api("/preview", {
        method: "POST",
        body: JSON.stringify({ url })
      });
    } catch (e) {
      // Preview is best-effort. Saving the link should still work.
      preview = {};
    }

    setStatus("Saving…");

    await api("/items/create", {
      method: "POST",
      body: JSON.stringify({
        url,
        final_url: preview.final_url || "",
        title: title || preview.title || url,
        description: preview.description || "",
        site_name: preview.site_name || "",
        favicon_url: preview.favicon_url || faviconFromUrl(url),
        preview_image_url: preview.preview_image_url || "",
        collection,
        tags_text: tags,
        notes,
        read_state: "unread"
      })
    });

    el("urlInput").value = "";
    el("titleInput").value = "";
    el("notesInput").value = "";

    updateComposerExpanded();
    setStatus("Saved.", "good");
    await loadItems();
  }

  async function updateItem(id, patch) {
    setStatus("Saving changes…");
    await api("/items/update", {
      method: "POST",
      body: JSON.stringify({ id, ...patch })
    });
    setStatus("Updated.", "good");
    await loadItems();
  }

  async function deleteItem(id) {
    setStatus("Deleting…");
    await api("/items/delete", {
      method: "POST",
      body: JSON.stringify({ id })
    });
    setStatus("Deleted.", "good");
    await loadItems();
  }

  async function archiveItem(id, archiveBtn) {
    if (archiveBtn) {
      archiveBtn.className = "archiveAction archiving";
      archiveBtn.textContent = "Archiving";
      archiveBtn.disabled = true;
    }

    setStatus("Archiving page snapshot", "working");

    try {
      const j = await api("/items/archive", {
        method: "POST",
        body: JSON.stringify({ id })
      });

      let deepIndexed = false;
      try {
        if (window.EchoStackFullText &&
            typeof window.EchoStackFullText.reindexItem === "function") {
          deepIndexed = await window.EchoStackFullText.reindexItem(id);
        }
      } catch (idxErr) {
        console.warn("Echo Stack Deep Search indexing failed:", idxErr);
      }

      if (j.already_archived) {
        setStatus(
          deepIndexed ? "Already archived. Deep Search index refreshed." : "Already archived.",
          "good"
        );
      } else {
        setStatus(
          deepIndexed ? "Archived and indexed for Deep Search." : "Archived.",
          "good"
        );
      }
    } catch (e) {
      setStatus(`Archive failed: ${e.message || String(e)}`, "bad");
    } finally {
      try {
        await loadItems();
      } catch (_) {
        // Keep the archive error visible if refresh itself fails.
      }
    }
  }

  function updateViewModeButton() {
    const btn = el("viewModeBtn");
    if (!btn) return;

    if (state.viewMode === "grid") {
      btn.textContent = "List view";
      btn.title = "Switch to full list view";
    } else {
      btn.textContent = "Grid view";
      btn.title = "Switch to compact grid view";
    }
  }

  function setViewMode(mode) {
    state.viewMode = mode === "grid" ? "grid" : "list";
    saveViewMode(state.viewMode);
    render();
  }

  function composerHasDetails() {
    return Boolean(
      (el("urlInput")?.value || "").trim() ||
      (el("titleInput")?.value || "").trim() ||
      (el("collectionInput")?.value || "").trim() ||
      (el("tagsInput")?.value || "").trim() ||
      (el("notesInput")?.value || "").trim()
    );
  }

  function setComposerExpanded(expanded) {
    const composer = document.querySelector(".composer");
    if (!composer) return;

    composer.classList.toggle("expanded", Boolean(expanded));
    composer.classList.toggle("collapsed", !expanded);
  }

  function updateComposerExpanded() {
    setComposerExpanded(composerHasDetails());
  }


  function setDeepSearchOpen(open) {
    const panel = el("deepSearchPanel");
    const btn = el("deepSearchToggleBtn");
    const isOpen = Boolean(open);

    if (panel) {
      panel.hidden = !isOpen;
      panel.classList.toggle("collapsed", !isOpen);
      panel.classList.toggle("expanded", isOpen);
    }

    if (btn) {
      btn.classList.toggle("active", isOpen);
      btn.setAttribute("aria-expanded", isOpen ? "true" : "false");
      btn.textContent = isOpen ? "Hide Deep Search" : "Deep Search";
    }

    if (isOpen) {
      setTimeout(() => {
        el("deepSearchInput")?.focus();
      }, 0);
    }
  }

  function toggleDeepSearchPanel() {
    const panel = el("deepSearchPanel");
    setDeepSearchOpen(panel ? panel.hidden : true);
  }

  function bind() {
    el("saveBtn")?.addEventListener("click", () => {
      saveNewItem().catch((e) => setStatus(e.message || String(e), "bad"));
    });
    

    el("viewModeBtn")?.addEventListener("click", () => {
      setViewMode(state.viewMode === "grid" ? "list" : "grid");
    });

    el("deepSearchToggleBtn")?.addEventListener("click", () => {
      toggleDeepSearchPanel();
    });

    el("refreshBtn")?.addEventListener("click", () => {
      loadItems().catch((e) => setStatus(e.message || String(e), "bad"));
    });

    el("importBookmarksBtn")?.addEventListener("click", () => {
      el("bookmarkImportFile")?.click();
    });

    el("exportBookmarksBtn")?.addEventListener("click", () => {
      exportBookmarksToHtmlFile().catch((e) => setStatus(e.message || String(e), "bad"));
    });

    el("bookmarkImportFile")?.addEventListener("change", () => {
      const input = el("bookmarkImportFile");
      const file = input?.files && input.files[0] ? input.files[0] : null;
      if (input) input.value = "";

      handleBookmarkImportFile(file).catch((e) => {
        setStatus(e.message || String(e), "bad");
        const importBtn = el("importBookmarksBtn");
        if (importBtn) {
          importBtn.disabled = false;
          importBtn.classList.remove("importing");
          importBtn.textContent = "Import bookmarks";
        }
      });
    });

    el("searchInput")?.addEventListener("input", () => {
      state.q = (el("searchInput").value || "").trim();
      clearTimeout(bind._timer);
      bind._timer = setTimeout(() => {
        loadItems().catch((e) => setStatus(e.message || String(e), "bad"));
      }, 220);
    });

    el("urlInput")?.addEventListener("focus", () => {
      setComposerExpanded(true);
    });

    el("urlInput")?.addEventListener("input", () => {
      setComposerExpanded(true);
    });

    for (const id of ["titleInput", "collectionInput", "tagsInput", "notesInput"]) {
      el(id)?.addEventListener("input", updateComposerExpanded);
      el(id)?.addEventListener("focus", () => setComposerExpanded(true));
    }

    el("urlInput")?.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        e.preventDefault();
        saveNewItem().catch((err) => setStatus(err.message || String(err), "bad"));
      }
    });
  }

  bind();
  bindKeyboardNavigation();
  bindItemContextMenuDismiss();
  setDeepSearchOpen(false);
  updateComposerExpanded();
  loadItems().catch((e) => setStatus(e.message || String(e), "bad"));
})();
