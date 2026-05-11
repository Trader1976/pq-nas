(() => {
  "use strict";

  const STYLE_ID = "pqnasFileAnnotationsStyle";
  const PANEL_ID = "fmFileAnnotationPanel";

  function $(id) {
    return document.getElementById(id);
  }

  function esc(s) {
    return String(s || "").replace(/[&<>"']/g, (c) => ({
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;"
    }[c]));
  }

  function installStyle() {
    if ($(STYLE_ID)) return;

    const style = document.createElement("style");
    style.id = STYLE_ID;
    style.textContent = `
      #${PANEL_ID}{
        grid-column:1 / -1;
        width:100%;
        box-sizing:border-box;
        margin-top:14px;
        padding:14px;
        border:1px solid rgba(var(--fg-rgb),0.14);
        border-radius:14px;
        background:rgba(255,255,255,0.035);
        display:grid;
        gap:10px;
      }
      #${PANEL_ID} .fmAnnoHead{
        display:flex;
        align-items:center;
        justify-content:space-between;
        gap:10px;
        min-width:0;
      }
      #${PANEL_ID} .fmAnnoTitle{
        font-weight:900;
        font-size:13px;
      }
      #${PANEL_ID} .fmAnnoStatus{
        font-size:11px;
        opacity:.72;
        text-align:right;
        overflow-wrap:anywhere;
      }
      #${PANEL_ID} textarea{
        display:block;
        width:100%;
        min-height:92px;
        resize:vertical;
        box-sizing:border-box;
        border-radius:10px;
        padding:10px 11px;
        font:inherit;
        font-size:13px;
        line-height:1.35;
        background:rgba(0,0,0,0.10);
        color:inherit;
        border:1px solid rgba(var(--fg-rgb),0.18);
      }
      #${PANEL_ID} .fmAnnoActions{
        display:flex;
        align-items:center;
        gap:8px;
        flex-wrap:wrap;
      }
      html[data-theme="win_classic"] #${PANEL_ID}{
        background:#fff;
        border-color:#b8b8b8;
      }
      html[data-theme="win_classic"] #${PANEL_ID} textarea{
        background:#fff;
        border-color:#9a9a9a;
      }
    `;
    document.head.appendChild(style);
  }

  function currentScope() {
    const FM = window.PQNAS_FILEMGR || {};
    const scope = FM.scope || {};

    if (scope.mode === "workspace" && scope.workspaceId) {
      return {
        scope_type: "workspace",
        scope_id: String(scope.workspaceId || ""),
        can_write: ["owner", "editor"].includes(String(scope.workspaceRole || "").toLowerCase())
      };
    }

    return {
      scope_type: "user",
      scope_id: "",
      can_write: true
    };
  }

  function propsPathToRel() {
    const txt = String($("propsPath")?.textContent || "").trim();
    if (!txt || txt === "/" || txt === ".") return ".";
    return txt.replace(/^\/+/, "") || ".";
  }

  function propsItemKind() {
    const title = String($("propsTitle")?.textContent || "").toLowerCase();
    if (title.includes("folder")) return "dir";
    if (title.includes("file")) return "file";
    return "unknown";
  }

  function shouldAttach() {
    const modal = $("propsModal");
    const body = $("propsBody");
    const title = String($("propsTitle")?.textContent || "");
    if (!modal || !body || !modal.classList.contains("show")) return false;
    if (!/^(File|Folder|Item) properties/i.test(title)) return false;
    return true;
  }

  async function apiGetNote(scope, path) {
    const qs = new URLSearchParams();
    qs.set("scope_type", scope.scope_type);
    if (scope.scope_id) qs.set("scope_id", scope.scope_id);
    qs.set("path", path);

    const r = await fetch(`/api/v4/file-annotations/note?${qs.toString()}`, {
      method: "GET",
      credentials: "include",
      cache: "no-store",
      headers: { "Accept": "application/json" }
    });

    const j = await r.json().catch(() => null);
    if (!r.ok || !j || !j.ok) {
      throw new Error((j && (j.message || j.error)) || `HTTP ${r.status}`);
    }
    return j;
  }

  async function apiSaveNote(scope, path, itemKind, description) {
    const r = await fetch("/api/v4/file-annotations/note", {
      method: "POST",
      credentials: "include",
      cache: "no-store",
      headers: {
        "Content-Type": "application/json",
        "Accept": "application/json"
      },
      body: JSON.stringify({
        scope_type: scope.scope_type,
        scope_id: scope.scope_id,
        path,
        item_kind: itemKind,
        description
      })
    });

    const j = await r.json().catch(() => null);
    if (!r.ok || !j || !j.ok) {
      throw new Error((j && (j.message || j.error)) || `HTTP ${r.status}`);
    }
    return j;
  }

  let activeSignature = "";

  function attachPanelSoon() {
    window.setTimeout(attachPanel, 0);
  }

  function attachPanel() {
    if (!shouldAttach()) return;

    installStyle();

    const body = $("propsBody");
    if (!body) return;

    const scope = currentScope();
    const path = propsPathToRel();
    const itemKind = propsItemKind();
    const signature = `${scope.scope_type}:${scope.scope_id}:${path}:${itemKind}`;

    const existing = $(PANEL_ID);
    if (existing && existing.dataset.signature === signature) return;
    if (existing) existing.remove();

    const panel = document.createElement("section");
    panel.id = PANEL_ID;
    panel.dataset.signature = signature;
    panel.innerHTML = `
      <div class="fmAnnoHead">
        <div class="fmAnnoTitle">Description</div>
        <div class="fmAnnoStatus mono">Loading…</div>
      </div>
      <textarea placeholder="Add a short note or description for this ${esc(itemKind === "dir" ? "folder" : "file")}…" ${scope.can_write ? "" : "readonly"}></textarea>
      <div class="fmAnnoActions">
        ${scope.can_write ? `<button class="btn secondary fmAnnoSave" type="button">Save description</button>` : ""}
        <button class="btn secondary fmAnnoReload" type="button">Reload</button>
      </div>
    `;

    body.appendChild(panel);

    const status = panel.querySelector(".fmAnnoStatus");
    const textarea = panel.querySelector("textarea");
    const saveBtn = panel.querySelector(".fmAnnoSave");
    const reloadBtn = panel.querySelector(".fmAnnoReload");

    async function load() {
      activeSignature = signature;
      status.textContent = "Loading…";

      try {
        const j = await apiGetNote(scope, path);
        if (activeSignature !== signature || !document.body.contains(panel)) return;

        const note = j.note || {};
        textarea.value = String(note.description || "");

        if (j.resolved && note.updated_at_epoch) {
          status.textContent = `Saved · ${new Date(Number(note.updated_at_epoch) * 1000).toLocaleString()}`;
        } else {
          status.textContent = scope.can_write ? "No description yet" : "No description";
        }
      } catch (e) {
        status.textContent = `Load failed: ${String(e && e.message ? e.message : e)}`;
      }
    }

    saveBtn?.addEventListener("click", async () => {
      const old = saveBtn.textContent;
      saveBtn.disabled = true;
      saveBtn.textContent = "Saving…";
      status.textContent = "Saving…";

      try {
        const j = await apiSaveNote(scope, path, itemKind, textarea.value);
        const note = j.note || {};
        status.textContent = note.updated_at_epoch
          ? `Saved · ${new Date(Number(note.updated_at_epoch) * 1000).toLocaleString()}`
          : "Saved";
      } catch (e) {
        status.textContent = `Save failed: ${String(e && e.message ? e.message : e)}`;
      } finally {
        saveBtn.disabled = false;
        saveBtn.textContent = old;
      }
    });

    reloadBtn?.addEventListener("click", load);
    load();
  }

  const mo = new MutationObserver(attachPanelSoon);

  window.addEventListener("DOMContentLoaded", () => {
    const modal = $("propsModal");
    const body = $("propsBody");
    const title = $("propsTitle");
    const path = $("propsPath");

    if (modal) mo.observe(modal, { attributes: true, attributeFilter: ["class", "aria-hidden"] });
    if (body) mo.observe(body, { childList: true });
    if (title) mo.observe(title, { childList: true, characterData: true, subtree: true });
    if (path) mo.observe(path, { childList: true, characterData: true, subtree: true });

    attachPanelSoon();
  });
})();
