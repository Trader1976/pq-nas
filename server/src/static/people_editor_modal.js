/* server/src/static/people_editor_modal.js
 * Detached People editor modal for DNA-Nexus People labels.
 */
(function () {
    "use strict";

    const STYLE_ID = "pqnasPeopleEditorModalStyle";
    const ROOT_ID = "pqnasPeopleEditorModal";

    let current = {
        contact: null,
        opts: null,
        drag: null
    };

    function $(id) {
        return document.getElementById(id);
    }

    function esc(s) {
        return String(s ?? "")
            .replaceAll("&", "&amp;")
            .replaceAll("<", "&lt;")
            .replaceAll(">", "&gt;")
            .replaceAll('"', "&quot;")
            .replaceAll("'", "&#39;");
    }

    function normalizeFingerprint(s) {
        return String(s || "")
            .trim()
            .replace(/[\s:-]+/g, "")
            .toLowerCase();
    }

    function fmtEpoch(epoch) {
        const n = Number(epoch || 0);
        if (!n) return "—";
        try {
            return new Date(n * 1000).toLocaleString();
        } catch (_) {
            return "—";
        }
    }

    async function apiJson(path, opts = {}) {
        const r = await fetch(path, {
            credentials: "include",
            cache: "no-store",
            ...opts
        });

        const text = await r.text();
        let j = {};
        try {
            j = text ? JSON.parse(text) : {};
        } catch (_) {
            throw new Error(`Unexpected response from ${path}`);
        }

        if (!r.ok || j.ok === false) {
            throw new Error(j.message || j.error || `HTTP ${r.status}`);
        }

        return j;
    }

    function installStyle() {
        if ($(STYLE_ID)) return;

        const style = document.createElement("style");
        style.id = STYLE_ID;
        style.textContent = `
#${ROOT_ID}{
    position:fixed;
    inset:0;
    z-index:30000;
    display:none;
    pointer-events:none;
}

#${ROOT_ID}.show{
    display:block;
}

#${ROOT_ID} .peopleEditorCard{
    position:absolute;
    top:86px;
    left:50%;
    transform:translateX(-50%);
    width:min(760px, calc(100vw - 34px));
    max-height:calc(100vh - 34px);
    overflow:auto;
    pointer-events:auto;
    border-radius:18px;
    border:1px solid rgba(var(--fg-rgb, 255,255,255),0.18);
    background:rgba(var(--bg-rgb, 12,12,14),0.96);
    color:var(--fg, inherit);
    box-shadow:0 26px 70px rgba(0,0,0,0.45);
    backdrop-filter:blur(14px);
}

#${ROOT_ID} .peopleEditorHead{
    display:flex;
    align-items:flex-start;
    justify-content:space-between;
    gap:14px;
    padding:16px 18px 14px;
    border-bottom:1px solid rgba(var(--fg-rgb, 255,255,255),0.12);
    cursor:move;
    user-select:none;
}

#${ROOT_ID} .peopleEditorHead h3{
    margin:0 0 4px 0;
    font-size:20px;
    line-height:1.15;
}

#${ROOT_ID} .peopleEditorSub{
    font-size:12px;
    opacity:.72;
    line-height:1.45;
}

#${ROOT_ID} .peopleEditorBody{
    padding:16px 18px 18px;
    display:grid;
    gap:12px;
}

#${ROOT_ID} .peopleEditorGrid{
    display:grid;
    grid-template-columns:repeat(auto-fit, minmax(230px, 1fr));
    gap:12px;
}

#${ROOT_ID} label{
    display:flex;
    flex-direction:column;
    gap:6px;
    font-size:12px;
    opacity:.86;
}

#${ROOT_ID} input,
#${ROOT_ID} select,
#${ROOT_ID} textarea{
    box-sizing:border-box;
    width:100%;
    border-radius:11px;
    border:1px solid rgba(var(--fg-rgb, 255,255,255),0.18);
    background:rgba(0,0,0,0.16);
    color:inherit;
    padding:10px 11px;
    font:inherit;
    font-size:13px;
}

#${ROOT_ID} textarea{
    min-height:110px;
    resize:vertical;
    line-height:1.4;
}

#${ROOT_ID} input[readonly]{
    opacity:.75;
}

#${ROOT_ID} .peopleEditorMeta{
    display:grid;
    grid-template-columns:repeat(auto-fit, minmax(210px, 1fr));
    gap:8px 14px;
    padding:12px;
    border-radius:14px;
    border:1px solid rgba(var(--fg-rgb, 255,255,255),0.11);
    background:rgba(255,255,255,0.035);
    font-size:12px;
}

#${ROOT_ID} .peopleEditorMeta b{
    display:inline-block;
    min-width:82px;
}

#${ROOT_ID} .peopleEditorFoot{
    display:flex;
    align-items:center;
    justify-content:space-between;
    gap:12px;
    flex-wrap:wrap;
    padding-top:4px;
}

#${ROOT_ID} .peopleEditorActions{
    display:flex;
    gap:10px;
    flex-wrap:wrap;
}

#${ROOT_ID} .peopleEditorStatus{
    font-size:12px;
    opacity:.8;
    overflow-wrap:anywhere;
}

#${ROOT_ID} .peopleEditorStatus.err{
    color:var(--fail, #ff6b6b);
    opacity:1;
}

#${ROOT_ID} .peopleEditorStatus.ok{
    color:var(--ok, #59d185);
    opacity:1;
}

html[data-theme="bright"] #${ROOT_ID} .peopleEditorCard{
    background:rgba(255,255,255,0.98);
    color:#10131a;
    border:1px solid rgba(0,0,0,0.18);
    box-shadow:0 26px 70px rgba(0,0,0,0.24);
}

html[data-theme="bright"] #${ROOT_ID} .peopleEditorHead{
    background:linear-gradient(180deg, rgba(255,255,255,0.98), rgba(244,246,250,0.98));
    border-bottom:1px solid rgba(0,0,0,0.12);
}

html[data-theme="bright"] #${ROOT_ID} .peopleEditorSub,
html[data-theme="bright"] #${ROOT_ID} label,
html[data-theme="bright"] #${ROOT_ID} .peopleEditorStatus{
    color:#303747;
    opacity:1;
}

html[data-theme="bright"] #${ROOT_ID} input,
html[data-theme="bright"] #${ROOT_ID} select,
html[data-theme="bright"] #${ROOT_ID} textarea{
    background:#fff;
    color:#10131a;
    border:1px solid rgba(0,0,0,0.22);
}

html[data-theme="bright"] #${ROOT_ID} input[readonly]{
    background:#f5f6f9;
    color:#303747;
    opacity:1;
}

html[data-theme="bright"] #${ROOT_ID} .peopleEditorMeta{
    background:#f8f9fc;
    color:#202635;
    border-color:rgba(0,0,0,0.12);
}


html[data-theme="win_classic"] #${ROOT_ID} .peopleEditorCard{
    background:#f2f2f2;
    color:#000;
    border:1px solid #888;
    border-radius:14px;
    box-shadow:8px 8px 0 rgba(0,0,0,0.22);
    backdrop-filter:none;
}

html[data-theme="win_classic"] #${ROOT_ID} .peopleEditorHead{
    background:linear-gradient(#ffffff,#dedede);
    border-bottom:1px solid #bbb;
}

html[data-theme="win_classic"] #${ROOT_ID} input,
html[data-theme="win_classic"] #${ROOT_ID} select,
html[data-theme="win_classic"] #${ROOT_ID} textarea{
    background:#fff;
    color:#000;
    border:1px solid #999;
}

html[data-theme="win_classic"] #${ROOT_ID} .peopleEditorMeta{
    background:#fff;
    border-color:#bbb;
}
        `.trim();

        style.textContent += `
/* people-editor-bright-theme-force */
html[data-theme="bright"] #pqnasPeopleEditorModal .peopleEditorCard,
html[data-theme="light"] #pqnasPeopleEditorModal .peopleEditorCard,
html:not([data-theme="dark"]):not([data-theme="cpunk_orange"]):not([data-theme="orange"]):not([data-theme="win_classic"]) #pqnasPeopleEditorModal .peopleEditorCard{
    background:#ffffff !important;
    color:#111827 !important;
    border:1px solid rgba(0,0,0,0.20) !important;
    box-shadow:0 26px 70px rgba(0,0,0,0.26) !important;
}

html[data-theme="bright"] #pqnasPeopleEditorModal .peopleEditorHead,
html[data-theme="light"] #pqnasPeopleEditorModal .peopleEditorHead,
html:not([data-theme="dark"]):not([data-theme="cpunk_orange"]):not([data-theme="orange"]):not([data-theme="win_classic"]) #pqnasPeopleEditorModal .peopleEditorHead{
    background:linear-gradient(180deg,#ffffff,#f3f4f6) !important;
    color:#111827 !important;
    border-bottom:1px solid rgba(0,0,0,0.14) !important;
}

html[data-theme="bright"] #pqnasPeopleEditorModal .peopleEditorTitle,
html[data-theme="bright"] #pqnasPeopleEditorModal .peopleEditorSub,
html[data-theme="bright"] #pqnasPeopleEditorModal label,
html[data-theme="bright"] #pqnasPeopleEditorModal .peopleEditorStatus,
html[data-theme="light"] #pqnasPeopleEditorModal .peopleEditorTitle,
html[data-theme="light"] #pqnasPeopleEditorModal .peopleEditorSub,
html[data-theme="light"] #pqnasPeopleEditorModal label,
html[data-theme="light"] #pqnasPeopleEditorModal .peopleEditorStatus,
html:not([data-theme="dark"]):not([data-theme="cpunk_orange"]):not([data-theme="orange"]):not([data-theme="win_classic"]) #pqnasPeopleEditorModal .peopleEditorTitle,
html:not([data-theme="dark"]):not([data-theme="cpunk_orange"]):not([data-theme="orange"]):not([data-theme="win_classic"]) #pqnasPeopleEditorModal .peopleEditorSub,
html:not([data-theme="dark"]):not([data-theme="cpunk_orange"]):not([data-theme="orange"]):not([data-theme="win_classic"]) #pqnasPeopleEditorModal label,
html:not([data-theme="dark"]):not([data-theme="cpunk_orange"]):not([data-theme="orange"]):not([data-theme="win_classic"]) #pqnasPeopleEditorModal .peopleEditorStatus{
    color:#111827 !important;
    opacity:1 !important;
}

html[data-theme="bright"] #pqnasPeopleEditorModal input,
html[data-theme="bright"] #pqnasPeopleEditorModal select,
html[data-theme="bright"] #pqnasPeopleEditorModal textarea,
html[data-theme="light"] #pqnasPeopleEditorModal input,
html[data-theme="light"] #pqnasPeopleEditorModal select,
html[data-theme="light"] #pqnasPeopleEditorModal textarea,
html:not([data-theme="dark"]):not([data-theme="cpunk_orange"]):not([data-theme="orange"]):not([data-theme="win_classic"]) #pqnasPeopleEditorModal input,
html:not([data-theme="dark"]):not([data-theme="cpunk_orange"]):not([data-theme="orange"]):not([data-theme="win_classic"]) #pqnasPeopleEditorModal select,
html:not([data-theme="dark"]):not([data-theme="cpunk_orange"]):not([data-theme="orange"]):not([data-theme="win_classic"]) #pqnasPeopleEditorModal textarea{
    background:#ffffff !important;
    color:#111827 !important;
    border:1px solid rgba(0,0,0,0.24) !important;
}

html[data-theme="bright"] #pqnasPeopleEditorModal input[readonly],
html[data-theme="light"] #pqnasPeopleEditorModal input[readonly],
html:not([data-theme="dark"]):not([data-theme="cpunk_orange"]):not([data-theme="orange"]):not([data-theme="win_classic"]) #pqnasPeopleEditorModal input[readonly]{
    background:#f3f4f6 !important;
    color:#374151 !important;
}

html[data-theme="bright"] #pqnasPeopleEditorModal .peopleEditorMeta,
html[data-theme="light"] #pqnasPeopleEditorModal .peopleEditorMeta,
html:not([data-theme="dark"]):not([data-theme="cpunk_orange"]):not([data-theme="orange"]):not([data-theme="win_classic"]) #pqnasPeopleEditorModal .peopleEditorMeta{
    background:#f9fafb !important;
    color:#111827 !important;
    border-color:rgba(0,0,0,0.14) !important;
}
`;
        document.head.appendChild(style);
    }

    function ensureRoot() {
        let root = $(ROOT_ID);
        if (root) return root;

        root = document.createElement("div");
        root.id = ROOT_ID;
        root.setAttribute("aria-hidden", "true");
        document.body.appendChild(root);
        return root;
    }

    function setStatus(msg, kind = "") {
        const el = document.querySelector(`#${ROOT_ID} .peopleEditorStatus`);
        if (!el) return;
        el.className = "peopleEditorStatus" + (kind ? " " + kind : "");
        el.textContent = msg || "";
    }

    function close() {
        const root = $(ROOT_ID);
        if (!root) return;

        root.classList.remove("show");
        root.setAttribute("aria-hidden", "true");
        root.innerHTML = "";

        current.contact = null;
        current.opts = null;
        current.drag = null;
    }

    function isOpen() {
        const root = $(ROOT_ID);
        return !!(root && root.classList.contains("show"));
    }

    function currentFingerprint() {
        const liveInput = $("peopleEditorFingerprint");
        const liveValue = liveInput ? liveInput.value : "";
        return normalizeFingerprint(liveValue || (current.contact && current.contact.subject_fingerprint) || "");
    }

    function submitCurrentForm() {
        const form = $("peopleEditorForm");
        if (!form || !isOpen()) return false;

        if (typeof form.requestSubmit === "function") {
            form.requestSubmit();
        } else {
            form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
        }

        return true;
    }

    function startDrag(ev) {
        const card = document.querySelector(`#${ROOT_ID} .peopleEditorCard`);
        const head = ev.target && ev.target.closest ? ev.target.closest(".peopleEditorHead") : null;
        if (!card || !head) return;
        if (ev.target.closest("button,input,select,textarea,a")) return;

        const rect = card.getBoundingClientRect();
        card.style.transform = "none";
        card.style.left = `${rect.left}px`;
        card.style.top = `${rect.top}px`;

        current.drag = {
            dx: ev.clientX - rect.left,
            dy: ev.clientY - rect.top
        };

        ev.preventDefault();
    }

    function moveDrag(ev) {
        const drag = current.drag;
        if (!drag) return;

        const card = document.querySelector(`#${ROOT_ID} .peopleEditorCard`);
        if (!card) return;

        const rect = card.getBoundingClientRect();
        const pad = 8;

        let left = ev.clientX - drag.dx;
        let top = ev.clientY - drag.dy;

        left = Math.max(pad, Math.min(left, window.innerWidth - rect.width - pad));
        top = Math.max(pad, Math.min(top, window.innerHeight - Math.min(rect.height, window.innerHeight - pad) - pad));

        card.style.left = `${left}px`;
        card.style.top = `${top}px`;
    }

    function stopDrag() {
        current.drag = null;
    }

    function render(contact, opts) {
        installStyle();

        const root = ensureRoot();
        current.contact = contact || {};
        current.opts = opts || {};

        const c = current.contact;
        const isExisting = !!String(c.subject_fingerprint || "").trim();

        root.innerHTML = `
            <div class="peopleEditorCard" role="dialog" aria-modal="false" aria-labelledby="peopleEditorTitle">
                <div class="peopleEditorHead">
                    <div>
                        <h3 id="peopleEditorTitle">${isExisting ? "Edit person" : "Add person"}</h3>
                        <div class="peopleEditorSub">
                            Private label for fingerprints, local users, and external DNA Connect identities.
                            This does not rename anyone globally.
                        </div>
                    </div>
                    <button class="btn secondary" type="button" data-action="close">Close</button>
                </div>

                <form class="peopleEditorBody" id="peopleEditorForm">
                    <div class="peopleEditorGrid">
                        <label>
                            Display name
                            <input id="peopleEditorDisplayName" type="text" maxlength="120" required
                                   value="${esc(c.display_name || "")}" placeholder="Leo">
                        </label>

                        <label>
                            Type
                            <select id="peopleEditorKind">
                                <option value="fingerprint" ${c.subject_kind === "fingerprint" ? "selected" : ""}>Fingerprint</option>
                                <option value="external_dna" ${c.subject_kind === "external_dna" ? "selected" : ""}>External DNA</option>
                                <option value="local_user" ${c.subject_kind === "local_user" ? "selected" : ""}>Local user</option>
                            </select>
                        </label>

                        <label>
                            Nickname
                            <input id="peopleEditorNickname" type="text" maxlength="120"
                                   value="${esc(c.nickname || "")}" placeholder="Optional">
                        </label>
                    </div>

                    <label>
                        Fingerprint
                        <input id="peopleEditorFingerprint" type="text" required ${isExisting ? "readonly" : ""}
                               value="${esc(c.subject_fingerprint || "")}" placeholder="hex fingerprint">
                    </label>

                    <label>
                        Notes
                        <textarea id="peopleEditorNotes" maxlength="2000"
                                  placeholder="Private note, e.g. John from motorbike club">${esc(c.notes || "")}</textarea>
                    </label>

                    <div class="peopleEditorMeta mono">
                        <div><b>Short FP</b> ${esc(c.subject_fingerprint_short || "—")}</div>
                        <div><b>Contact ID</b> ${esc(c.id || "—")}</div>
                        <div><b>Created</b> ${esc(fmtEpoch(c.created_at_epoch))}</div>
                        <div><b>Updated</b> ${esc(fmtEpoch(c.updated_at_epoch))}</div>
                    </div>

                    <div class="peopleEditorFoot">
                        <div class="peopleEditorStatus mono"></div>
                        <div class="peopleEditorActions">
                            <button class="btn" id="peopleEditorSave" type="submit">Save</button>
                            <button class="btn secondary" type="button" data-action="close">Cancel</button>
                        </div>
                    </div>
                </form>
            </div>
        `;

        root.classList.add("show");
        root.setAttribute("aria-hidden", "false");

        const card = root.querySelector(".peopleEditorCard");
        if (card) {
            card.style.left = "50%";
            card.style.top = "86px";
            card.style.transform = "translateX(-50%)";
        }

        root.querySelector(".peopleEditorHead")?.addEventListener("mousedown", startDrag);

        for (const btn of root.querySelectorAll("[data-action='close']")) {
            btn.addEventListener("click", close);
        }

        const form = $("peopleEditorForm");
        const saveBtn = $("peopleEditorSave");

        form?.addEventListener("submit", async (ev) => {
            ev.preventDefault();

            const fp = normalizeFingerprint($("peopleEditorFingerprint")?.value || "");
            const displayName = String($("peopleEditorDisplayName")?.value || "").trim();
            const subjectKind = String($("peopleEditorKind")?.value || "fingerprint").trim();
            const nickname = String($("peopleEditorNickname")?.value || "").trim();
            const notes = String($("peopleEditorNotes")?.value || "").trim();

            if (!fp) {
                setStatus("Fingerprint is required.", "err");
                return;
            }

            if (!displayName) {
                setStatus("Display name is required.", "err");
                return;
            }

            const old = saveBtn ? saveBtn.textContent : "";
            if (saveBtn) {
                saveBtn.disabled = true;
                saveBtn.textContent = "Saving…";
            }
            setStatus("Saving…");

            try {
                const j = await apiJson("/api/v4/people/upsert", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        subject_fingerprint: fp,
                        display_name: displayName,
                        subject_kind: subjectKind,
                        nickname,
                        notes
                    })
                });

                setStatus("Saved.", "ok");

                const onSaved = current.opts && current.opts.onSaved;
                close();

                if (typeof onSaved === "function") {
                    await onSaved(j);
                }
            } catch (e) {
                setStatus(`Save failed: ${String(e && e.message ? e.message : e)}`, "err");
                if (saveBtn) {
                    saveBtn.disabled = false;
                    saveBtn.textContent = old || "Save";
                }
            }
        });

        /* people-editor-no-autofocus-v1
           Keep focus where it was opened from. This lets Space toggle the
           detached editor from the selected People card instead of typing
           into the Display name field. */
    }

    document.addEventListener("mousemove", moveDrag);
    document.addEventListener("mouseup", stopDrag);
    document.addEventListener("keydown", (ev) => {
        const open = isOpen();

        if (open && (ev.ctrlKey || ev.metaKey) && String(ev.key || "").toLowerCase() === "s") {
            ev.preventDefault();
            ev.stopPropagation();
            submitCurrentForm();
            return;
        }

        if (ev.key === "Escape" && open) {
            close();
        }
    });

    window.PQPeopleEditor = {
        open: render,
        close,
        isOpen,
        saveCurrent: submitCurrentForm,
        currentFingerprint
    };
})();
