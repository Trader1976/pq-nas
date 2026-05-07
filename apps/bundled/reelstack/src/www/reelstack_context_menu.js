(() => {
  "use strict";

  let api = null;
  let menu = null;
  let installed = false;

  function basename(path) {
    const parts = String(path || "").split("/").filter(Boolean);
    return parts.length ? parts[parts.length - 1] : String(path || "");
  }

  function ensureMenu() {
    if (menu) return menu;

    menu = document.createElement("div");
    menu.className = "rsContextMenu";
    menu.hidden = true;
    menu.setAttribute("role", "menu");

    document.body.appendChild(menu);
    return menu;
  }

  function hideMenu() {
    if (menu) menu.hidden = true;
  }

  function placeMenu(x, y) {
    const m = ensureMenu();
    m.hidden = false;

    const rect = m.getBoundingClientRect();
    const pad = 8;

    const left = Math.max(pad, Math.min(x, window.innerWidth - rect.width - pad));
    const top = Math.max(pad, Math.min(y, window.innerHeight - rect.height - pad));

    m.style.left = `${left}px`;
    m.style.top = `${top}px`;
  }

  function makeButton(label, hint, danger, onClick) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.setAttribute("role", "menuitem");
    if (danger) btn.classList.add("rsDanger");

    const text = document.createElement("span");
    text.textContent = label;

    const h = document.createElement("span");
    h.className = "rsContextMenuHint";
    h.textContent = hint || "";

    btn.appendChild(text);
    btn.appendChild(h);

    btn.addEventListener("click", async (ev) => {
      ev.preventDefault();
      ev.stopPropagation();

      const path = menu ? menu.dataset.rsPath : "";
      hideMenu();

      try {
        await onClick(path);
      } catch (e) {
        if (api && typeof api.setStatus === "function") {
          api.setStatus(e && e.message ? e.message : String(e));
        } else {
          console.error(e);
        }
      }
    });

    return btn;
  }

  function videoForPath(path) {
    if (!api || typeof api.videoByPath !== "function") return null;
    return api.videoByPath(path);
  }

  function renderMenu(path) {
    const m = ensureMenu();
    m.innerHTML = "";
    m.dataset.rsPath = path || "";

    const title = document.createElement("div");
    title.className = "rsContextMenuTitle";
    title.textContent = basename(path || "Video");
    m.appendChild(title);

    m.appendChild(makeButton("Play", "Enter", false, async (p) => {
      const v = videoForPath(p);
      if (v && api.openPlayer) api.openPlayer(v);
    }));

    m.appendChild(makeButton("Edit metadata", "Space", false, async (p) => {
      const v = videoForPath(p);
      if (v && api.editMetadata) await api.editMetadata(v);
    }));

    m.appendChild(makeButton("Rename", "", false, async (p) => {
      const v = videoForPath(p);
      if (v && api.renameVideo) await api.renameVideo(v);
    }));

    m.appendChild(makeButton("Share link", "", false, async (p) => {
      const v = videoForPath(p);
      if (v && api.shareVideo) await api.shareVideo(v);
    }));

    m.appendChild(makeButton("Download", "", false, async (p) => {
      if (!api.downloadUrl) return;
      const a = document.createElement("a");
      a.href = api.downloadUrl(p);
      a.download = basename(p);
      document.body.appendChild(a);
      a.click();
      a.remove();
    }));

    m.appendChild(makeButton("Delete", "", true, async (p) => {
      const v = videoForPath(p);
      if (v && api.deleteVideo) await api.deleteVideo(v);
    }));
  }

  function onContextMenu(ev) {
    const card = ev.target && ev.target.closest
      ? ev.target.closest(".rsCard[data-rs-path]")
      : null;

    if (!card) return;

    const path = card.dataset.rsPath || "";
    if (!path) return;

    ev.preventDefault();
    ev.stopPropagation();

    if (api && typeof api.selectPath === "function") {
      api.selectPath(path, { focus: true });
    }

    renderMenu(path);
    placeMenu(ev.clientX, ev.clientY);
  }

  function onKeydown(ev) {
    if (ev.key === "Escape") {
      hideMenu();
      return;
    }

    if ((ev.key === "ContextMenu" || (ev.shiftKey && ev.key === "F10")) && api) {
      const selected = typeof api.selectedVideo === "function" ? api.selectedVideo() : null;
      if (!selected || !selected.path) return;

      ev.preventDefault();
      ev.stopPropagation();

      if (typeof api.selectPath === "function") {
        api.selectPath(selected.path, { focus: true });
      }

      const card = document.querySelector(`.rsCard[data-rs-path="${CSS.escape(selected.path)}"]`);
      const r = card ? card.getBoundingClientRect() : { left: 80, top: 80 };

      renderMenu(selected.path);
      placeMenu(r.left + 24, r.top + 24);
    }
  }

  function install(appApi) {
    api = appApi || api;
    if (installed) return;
    installed = true;

    ensureMenu();

    document.addEventListener("contextmenu", onContextMenu, true);
    document.addEventListener("click", (ev) => {
      if (menu && !menu.hidden && !menu.contains(ev.target)) hideMenu();
    }, true);
    document.addEventListener("keydown", onKeydown, true);
    window.addEventListener("blur", hideMenu);
    window.addEventListener("scroll", hideMenu, true);
    window.addEventListener("resize", hideMenu);
  }

  window.PQNAS_REELSTACK_CONTEXT_MENU = { install };

  window.addEventListener("pqnas-reelstack-ready", (ev) => {
    install(ev.detail);
  });

  if (window.PQNAS_REELSTACK_APP) {
    install(window.PQNAS_REELSTACK_APP);
  }
})();
