/* server/src/static/people.js
 * DNA-Nexus People UI
 *
 * Private per-user friendly names for fingerprints, workspace collaborators,
 * external DNA Connect members, and future @mentions/locks/activity/access maps.
 */
(function () {
    "use strict";

    function tr(key, vars = null, fallback = "") {
        try {
            if (window.PQNAS_I18N && typeof window.PQNAS_I18N.t === "function") {
                return window.PQNAS_I18N.t(key, vars, fallback || key);
            }
        } catch (_) {}
        return fallback || key;
    }

    const state = {
        ctx: null,
        contacts: [],
        loading: false,
        error: "",
        notice: "",
        noticeKind: "ok",
        editing: null,
        search: "",
        selectedFp: "",
        detailOpenFp: ""
    };

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

    function shortFp(fp) {
        const s = String(fp || "");
        if (s.length <= 16) return s;
        return `${s.slice(0, 8)}…${s.slice(-6)}`;
    }

    function kindLabel(kind) {
        if (kind === "local_user") return tr("people.kind.local_user", null, "Local user");
        if (kind === "external_dna") return tr("people.kind.external_dna", null, "External DNA");
        return tr("people.kind.fingerprint", null, "Fingerprint");
    }

    const PEOPLE_RECENT_KEY = "pqnas_people_recently_added_v1";
    const PEOPLE_RECENT_TTL_MS = 24 * 60 * 60 * 1000;

    function readRecentlyAddedPeople() {
        try {
            const raw = localStorage.getItem(PEOPLE_RECENT_KEY);
            const obj = raw ? JSON.parse(raw) : {};
            return obj && typeof obj === "object" ? obj : {};
        } catch (_) {
            return {};
        }
    }

    function writeRecentlyAddedPeople(obj) {
        try {
            localStorage.setItem(PEOPLE_RECENT_KEY, JSON.stringify(obj || {}));
        } catch (_) {
        }
    }

    function recentlyAddedAt(fp) {
        const clean = normalizeFingerprint(fp);
        if (!clean) return 0;

        const now = Date.now();
        const obj = readRecentlyAddedPeople();
        let changed = false;

        for (const [k, v] of Object.entries(obj)) {
            const ts = Number(v);
            if (!Number.isFinite(ts) || now - ts > PEOPLE_RECENT_TTL_MS) {
                delete obj[k];
                changed = true;
            }
        }

        if (changed) writeRecentlyAddedPeople(obj);

        const ts = Number(obj[clean] || 0);
        if (!Number.isFinite(ts) || ts <= 0) return 0;
        if (now - ts > PEOPLE_RECENT_TTL_MS) return 0;
        return ts;
    }

    function isRecentlyAddedPerson(fp) {
        return recentlyAddedAt(fp) > 0;
    }

    function sortNewFirst(list) {
        return [...(Array.isArray(list) ? list : [])].sort((a, b) => {
            const an = recentlyAddedAt(a && a.subject_fingerprint);
            const bn = recentlyAddedAt(b && b.subject_fingerprint);
            if (an !== bn) return bn - an;

            const al = String(a && (a.display_name || a.subject_fingerprint) || "");
            const bl = String(b && (b.display_name || b.subject_fingerprint) || "");
            return al.localeCompare(bl);
        });
    }

    function filterContacts() {
        const q = String(state.search || "").trim().toLowerCase();
        const source = Array.isArray(state.contacts) ? state.contacts : [];

        if (!q) return sortNewFirst(source);

        return sortNewFirst(source.filter((c) => {
            const hay = [
                c.display_name,
                c.nickname,
                c.notes,
                c.subject_kind,
                c.subject_fingerprint,
                c.subject_fingerprint_short
            ].join(" ").toLowerCase();

            return hay.includes(q);
        }));
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
            throw new Error(tr("people.error.unexpected_response", { path }, `Unexpected response from ${path}`));
        }

        if (!r.ok || j.ok === false) {
            throw new Error(j.message || j.error || `HTTP ${r.status}`);
        }

        return j;
    }

    async function loadContacts() {
        state.loading = true;
        state.error = "";
        draw();

        try {
            const j = await apiJson("/api/v4/people/list");
            state.contacts = Array.isArray(j.contacts) ? j.contacts : [];
            ensureSelection();
        } catch (e) {
            state.error = String(e && e.message ? e.message : e);
        } finally {
            state.loading = false;
            draw();
        }
    }

    async function saveContactFromForm(ev) {
        ev.preventDefault();

        const fp = normalizeFingerprint(document.getElementById("peopleFingerprint")?.value || "");
        const displayName = String(document.getElementById("peopleDisplayName")?.value || "").trim();
        const kind = String(document.getElementById("peopleKind")?.value || "fingerprint").trim();
        const nickname = String(document.getElementById("peopleNickname")?.value || "").trim();
        const notes = String(document.getElementById("peopleNotes")?.value || "").trim();

        if (!fp) {
            state.notice = tr("people.error.fingerprint_required", null, "Fingerprint is required.");
            state.noticeKind = "err";
            draw();
            return;
        }

        if (!displayName) {
            state.notice = tr("people.error.display_name_required", null, "Display name is required.");
            state.noticeKind = "err";
            draw();
            return;
        }

        try {
            await apiJson("/api/v4/people/upsert", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    subject_fingerprint: fp,
                    display_name: displayName,
                    subject_kind: kind,
                    nickname,
                    notes
                })
            });

            state.editing = null;
            state.notice = tr("people.saved", null, "Person saved.");
            state.noticeKind = "ok";
            await loadContacts();
        } catch (e) {
            state.notice = tr("people.save_failed", { error: String(e && e.message ? e.message : e) }, `Save failed: ${String(e && e.message ? e.message : e)}`);
            state.noticeKind = "err";
            draw();
        }
    }



    function injectPeopleConfirmCss() {
        if (document.getElementById("peopleConfirmCss")) return;

        const style = document.createElement("style");
        style.id = "peopleConfirmCss";
        style.textContent = `
.peopleConfirmBackdrop{
    position:fixed;
    inset:0;
    z-index:100000;
    display:flex;
    align-items:center;
    justify-content:center;
    padding:18px;
    background:rgba(0,0,0,0.55);
    backdrop-filter:blur(6px);
    -webkit-backdrop-filter:blur(6px);
}

.peopleConfirmCard{
    width:min(640px, calc(100vw - 24px));
    max-height:min(84vh, 900px);
    display:flex;
    flex-direction:column;
    overflow:hidden;
    border:1px solid var(--border2, rgba(120,120,120,0.45));
    border-radius:18px;
    background:linear-gradient(180deg, var(--panel2, #f8f8f8), var(--panel, #eeeeee));
    box-shadow:0 18px 70px rgba(0,0,0,0.42);
    color:var(--fg, #111);
}

.peopleConfirmHead{
    display:flex;
    align-items:center;
    justify-content:space-between;
    gap:12px;
    padding:14px 16px;
    border-bottom:1px solid var(--border2, rgba(120,120,120,0.35));
    background:rgba(0,0,0,0.08);
}

.peopleConfirmTitle{
    font-weight:950;
    letter-spacing:.2px;
    font-size:16px;
}

.peopleConfirmSub{
    margin-top:4px;
    font-size:12px;
    color:var(--fg-dim, rgba(0,0,0,0.65));
}

.peopleConfirmBody{
    padding:16px;
    display:grid;
    grid-template-columns:130px minmax(0, 1fr);
    gap:10px 14px;
    overflow:auto;
    min-height:0;
}

.peopleConfirmKey{
    color:var(--fg-dim, rgba(0,0,0,0.68));
    font-weight:850;
}

.peopleConfirmValue{
    color:var(--fg, #111);
    overflow-wrap:anywhere;
    white-space:pre-wrap;
}

.peopleConfirmValue.mono{
    font-family:var(--mono, ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace);
    font-size:12px;
}

.peopleConfirmNote{
    grid-column:1 / -1;
    padding:10px 12px;
    border:1px solid rgba(var(--warn-rgb, 180,120,20),0.35);
    border-radius:14px;
    background:rgba(var(--warn-rgb, 180,120,20),0.10);
    color:var(--fg, #111);
    font-weight:850;
}

.peopleConfirmFoot{
    display:flex;
    align-items:center;
    gap:12px;
    padding:12px 16px;
    border-top:1px solid var(--border2, rgba(120,120,120,0.35));
    background:rgba(0,0,0,0.08);
}

.peopleConfirmBtn{
    border:1px solid var(--border2, rgba(120,120,120,0.45));
    border-radius:14px;
    padding:9px 14px;
    font:inherit;
    font-weight:850;
    color:var(--fg, #111);
    background:linear-gradient(180deg, rgba(255,255,255,0.20), rgba(0,0,0,0.04));
    cursor:pointer;
}

.peopleConfirmBtn:hover{
    filter:brightness(1.05);
}

.peopleConfirmBtn.secondary{
    opacity:.90;
}

.peopleConfirmBtn.danger{
    border-color:rgba(var(--fail-rgb, 180,40,40),0.48);
    background:rgba(var(--fail-rgb, 180,40,40),0.14);
    color:var(--fg, #111);
}

html[data-theme="dark"] .peopleConfirmBackdrop,
html[data-theme="cpunk_orange"] .peopleConfirmBackdrop,
html[data-theme="orange"] .peopleConfirmBackdrop{
    background:rgba(0,0,0,0.62);
}

html[data-theme="bright"] .peopleConfirmBackdrop,
html[data-theme="win_classic"] .peopleConfirmBackdrop{
    background:rgba(0,0,0,0.38);
}
`;
        document.head.appendChild(style);
    }

    function openPeopleConfirmModal(opts = {}) {
        injectPeopleConfirmCss();

        return new Promise((resolve) => {
            const options = opts || {};

            const modal = document.createElement("div");
            modal.className = "peopleConfirmBackdrop";
            modal.setAttribute("role", "dialog");
            modal.setAttribute("aria-modal", "true");

            const card = document.createElement("div");
            card.className = "peopleConfirmCard";

            const head = document.createElement("div");
            head.className = "peopleConfirmHead";

            const headText = document.createElement("div");

            const title = document.createElement("div");
            title.className = "peopleConfirmTitle";
            title.textContent = options.title || tr("people.confirm.title", null, "Confirm action");

            const sub = document.createElement("div");
            sub.className = "peopleConfirmSub";
            sub.textContent = options.subtitle || "";

            headText.appendChild(title);
            if (sub.textContent) headText.appendChild(sub);
            head.appendChild(headText);

            const body = document.createElement("div");
            body.className = "peopleConfirmBody";

            const rows = Array.isArray(options.rows) ? options.rows : [];
            for (const row of rows) {
                const k = document.createElement("div");
                k.className = "peopleConfirmKey";
                k.textContent = String(row.label || "");

                const v = document.createElement("div");
                v.className = row.mono ? "peopleConfirmValue mono" : "peopleConfirmValue";
                v.textContent = String(row.value || "");

                body.appendChild(k);
                body.appendChild(v);
            }

            if (options.note) {
                const note = document.createElement("div");
                note.className = "peopleConfirmNote";
                note.textContent = String(options.note || "");
                body.appendChild(note);
            }

            const foot = document.createElement("div");
            foot.className = "peopleConfirmFoot";

            const spacer = document.createElement("div");
            spacer.style.flex = "1 1 auto";

            const cancelBtn = document.createElement("button");
            cancelBtn.type = "button";
            cancelBtn.className = "peopleConfirmBtn secondary";
            cancelBtn.textContent = options.cancelText || tr("people.cancel", null, "Cancel");

            const okBtn = document.createElement("button");
            okBtn.type = "button";
            okBtn.className = options.danger ? "peopleConfirmBtn danger" : "peopleConfirmBtn";
            okBtn.textContent = options.confirmText || tr("people.confirm.ok", null, "OK");

            foot.appendChild(spacer);
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

            window.setTimeout(() => {
                if (options.danger) cancelBtn.focus();
                else okBtn.focus();
            }, 0);
        });
    }


    function injectPeopleModalForceCss() {
        if (document.getElementById("peopleModalForceCss")) return;

        const style = document.createElement("style");
        style.id = "peopleModalForceCss";
        style.textContent = `
/* People page modal compatibility: supports both old .modal/.modalCard and new peopleConfirm classes. */
.peopleConfirmBackdrop,
.modal.show{
    position:fixed !important;
    inset:0 !important;
    z-index:100000 !important;
    display:flex !important;
    align-items:center !important;
    justify-content:center !important;
    padding:18px !important;
    background:rgba(0,0,0,0.55) !important;
    backdrop-filter:blur(6px);
    -webkit-backdrop-filter:blur(6px);
}

.peopleConfirmCard,
.modal.show > .modalCard{
    width:min(640px, calc(100vw - 24px)) !important;
    max-height:min(84vh, 900px) !important;
    display:flex !important;
    flex-direction:column !important;
    overflow:hidden !important;
    border:1px solid var(--border2, rgba(120,120,120,0.45)) !important;
    border-radius:18px !important;
    background:linear-gradient(180deg, var(--panel2, #f8f8f8), var(--panel, #eeeeee)) !important;
    box-shadow:0 18px 70px rgba(0,0,0,0.42) !important;
    color:var(--fg, #111) !important;
}

.peopleConfirmHead,
.modal.show .modalHead{
    display:flex !important;
    align-items:center !important;
    justify-content:space-between !important;
    gap:12px !important;
    padding:14px 16px !important;
    border-bottom:1px solid var(--border2, rgba(120,120,120,0.35)) !important;
    background:rgba(0,0,0,0.08) !important;
}

.peopleConfirmTitle,
.modal.show .modalTitle{
    font-weight:950 !important;
    letter-spacing:.2px !important;
    font-size:16px !important;
}

.peopleConfirmSub,
.modal.show .modalSub{
    margin-top:4px !important;
    font-size:12px !important;
    color:var(--fg-dim, rgba(0,0,0,0.65)) !important;
}

.peopleConfirmBody,
.modal.show .modalBody{
    padding:16px !important;
    display:grid !important;
    grid-template-columns:130px minmax(0, 1fr) !important;
    gap:10px 14px !important;
    overflow:auto !important;
    min-height:0 !important;
}

.peopleConfirmKey,
.modal.show .k{
    color:var(--fg-dim, rgba(0,0,0,0.68)) !important;
    font-weight:850 !important;
}

.peopleConfirmValue,
.modal.show .v{
    color:var(--fg, #111) !important;
    overflow-wrap:anywhere !important;
    white-space:pre-wrap !important;
}

.peopleConfirmValue.mono,
.modal.show .mono{
    font-family:var(--mono, ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace) !important;
    font-size:12px !important;
}

.peopleConfirmNote{
    grid-column:1 / -1 !important;
    padding:10px 12px !important;
    border:1px solid rgba(var(--warn-rgb, 180,120,20),0.35) !important;
    border-radius:14px !important;
    background:rgba(var(--warn-rgb, 180,120,20),0.10) !important;
    color:var(--fg, #111) !important;
    font-weight:850 !important;
}

.peopleConfirmFoot,
.modal.show .modalFoot{
    display:flex !important;
    align-items:center !important;
    gap:12px !important;
    padding:12px 16px !important;
    border-top:1px solid var(--border2, rgba(120,120,120,0.35)) !important;
    background:rgba(0,0,0,0.08) !important;
}

.peopleConfirmBtn,
.modal.show .btn{
    border:1px solid var(--border2, rgba(120,120,120,0.45)) !important;
    border-radius:14px !important;
    padding:9px 14px !important;
    font:inherit !important;
    font-weight:850 !important;
    color:var(--fg, #111) !important;
    background:linear-gradient(180deg, rgba(255,255,255,0.20), rgba(0,0,0,0.04)) !important;
    cursor:pointer !important;
}

.peopleConfirmBtn.danger,
.modal.show .btn.danger{
    border-color:rgba(var(--fail-rgb, 180,40,40),0.48) !important;
    background:rgba(var(--fail-rgb, 180,40,40),0.14) !important;
    color:var(--fg, #111) !important;
}

html[data-theme="bright"] .peopleConfirmBackdrop,
html[data-theme="bright"] .modal.show,
html[data-theme="win_classic"] .peopleConfirmBackdrop,
html[data-theme="win_classic"] .modal.show{
    background:rgba(0,0,0,0.38) !important;
}
`;
        document.head.appendChild(style);
    }

    async function deleteContact(fp, label) {
        injectPeopleModalForceCss();
        const displayLabel = label || shortFp(fp);
        const ok = await openPeopleConfirmModal({
            title: tr("people.remove.title", null, "Remove from People?"),
            subtitle: tr("people.remove.subtitle", null, "This removes your private label for this person."),
            rows: [
                { label: tr("people.remove.person", null, "Person"), value: displayLabel, mono: true },
                { label: tr("people.remove.fingerprint", null, "Fingerprint"), value: fp, mono: true },
            ],
            note: tr("people.remove.note", null, "This does not delete the real user, external member, or any files. It only removes the saved People label."),
            confirmText: tr("people.remove.confirm", null, "Remove"),
            cancelText: tr("people.cancel", null, "Cancel"),
            danger: true,
        });
        if (!ok) return;

        try {
            await apiJson("/api/v4/people/delete", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ subject_fingerprint: fp })
            });

            state.notice = tr("people.deleted", null, "Person removed.");
            state.noticeKind = "ok";
            await loadContacts();
        } catch (e) {
            state.notice = tr("people.delete_failed", { error: String(e && e.message ? e.message : e) }, `Delete failed: ${String(e && e.message ? e.message : e)}`);
            state.noticeKind = "err";
            draw();
        }
    }

    function openPeopleEditor(contact) {
        const c = contact || {};
        const editor = window.PQPeopleEditor;

        if (!editor || typeof editor.open !== "function") {
            state.editing = { ...c };
            state.notice = "";
            draw();
            return;
        }

        state.editing = null;
        state.notice = "";
        state.detailOpenFp = c.subject_fingerprint || "";

        editor.open(c, {
            onSaved: async () => {
                state.notice = tr("people.saved", null, "Person saved.");
                state.noticeKind = "ok";
                await loadContacts();
            }
        });
    }

    function beginAdd() {
        openPeopleEditor({
            subject_fingerprint: "",
            subject_kind: "fingerprint",
            display_name: "",
            nickname: "",
            notes: ""
        });
    }

    function beginEdit(fp) {
        const c = state.contacts.find((x) => x.subject_fingerprint === fp);
        if (!c) return;
        setSelectedFp(fp, { focus: false, scroll: false });
        openPeopleEditor({ ...c });
    }

    function renderEditor() {
        const c = state.editing;
        if (!c) return "";

        const isExisting = !!c.subject_fingerprint;

        return `
            <div class="card" style="padding:16px; margin-top:12px; border-color:rgba(var(--accent-rgb),0.35);">
                <h3 style="margin:0 0 8px 0; font-size:17px;">${isExisting ? tr("people.editor.edit_title", null, "Edit person") : tr("people.editor.add_title", null, "Add person")}</h3>
                <div class="mini" style="line-height:1.5; margin-bottom:12px;">
                    ${tr("people.editor.private_label_desc", null, "This only changes your private label for this fingerprint. It does not rename the real user globally.")}
                </div>

                <form id="peopleEditForm">
                    <div style="display:grid; grid-template-columns:repeat(auto-fit,minmax(240px,1fr)); gap:12px;">
                        <label class="mini" style="display:flex; flex-direction:column; gap:6px;">
                            ${tr("people.display_name", null, "Display name")}\n                            <input id="peopleDisplayName" type="text" maxlength="120" required
                                   value="${esc(c.display_name || "")}"
                                   placeholder="${tr("people.display_name_placeholder", null, "Leo")}">
                        </label>

                        <label class="mini" style="display:flex; flex-direction:column; gap:6px;">
                            ${tr("people.kind.type", null, "Type")}\n                            <select id="peopleKind">
                                <option value="fingerprint" ${c.subject_kind === "fingerprint" ? "selected" : ""}>${tr("people.kind.fingerprint", null, "Fingerprint")}</option>
                                <option value="external_dna" ${c.subject_kind === "external_dna" ? "selected" : ""}>${tr("people.kind.external_dna", null, "External DNA")}</option>
                                <option value="local_user" ${c.subject_kind === "local_user" ? "selected" : ""}>${tr("people.kind.local_user", null, "Local user")}</option>
                            </select>
                        </label>

                        <label class="mini" style="display:flex; flex-direction:column; gap:6px;">
                            ${tr("people.nickname", null, "Nickname")}\n                            <input id="peopleNickname" type="text" maxlength="120"
                                   value="${esc(c.nickname || "")}"
                                   placeholder="${tr("people.optional", null, "Optional")}">
                        </label>
                    </div>

                    <label class="mini" style="display:flex; flex-direction:column; gap:6px; margin-top:12px;">
                        ${tr("people.kind.fingerprint", null, "Fingerprint")}\n                        <input id="peopleFingerprint" type="text" required ${isExisting ? "readonly" : ""}
                               value="${esc(c.subject_fingerprint || "")}"
                               placeholder="${tr("people.hex_fingerprint", null, "hex fingerprint")}">
                    </label>

                    <label class="mini" style="display:flex; flex-direction:column; gap:6px; margin-top:12px;">
                        ${tr("people.notes", null, "Notes")}\n                        <textarea id="peopleNotes" maxlength="2000" rows="4"
                                  placeholder="${tr("people.notes_placeholder", null, "Private note, e.g. John from motorbike club")}">${esc(c.notes || "")}</textarea>
                    </label>

                    <div style="display:flex; gap:10px; flex-wrap:wrap; margin-top:14px;">
                        <button class="btn" type="submit">${tr("people.save", null, "Save")}</button>
                        <button class="btn secondary" id="peopleCancelEdit" type="button">${tr("people.cancel", null, "Cancel")}</button>
                    </div>
                </form>
            </div>
        `;
    }


    let peopleKeyboardInstalled = false;

    function contactLabel(c) {
        const nickname = String((c && c.nickname) || "").trim();
        if (nickname) return nickname;

        const short = String((c && c.subject_fingerprint_short) || "").trim();
        if (short) return short;

        const fp = String((c && c.subject_fingerprint) || "").trim();
        return shortFp(fp);
    }

    function contactDisplayNameLine(c) {
        const displayName = String((c && c.display_name) || "").trim();
        if (!displayName) return "";

        const nickname = String((c && c.nickname) || "").trim();
        const fp = String((c && c.subject_fingerprint) || "").trim();
        const fpShort = String((c && c.subject_fingerprint_short) || shortFp(fp)).trim();

        if (displayName === nickname) return "";
        if (displayName === fpShort) return "";
        if (normalizeFingerprint(displayName) && normalizeFingerprint(displayName) === normalizeFingerprint(fp)) return "";

        return displayName;
    }

    function contactInitials(c) {
        const label = contactLabel(c).trim();
        if (!label) return "?";

        const words = label
            .replace(/[^\p{L}\p{N}\s_-]+/gu, " ")
            .trim()
            .split(/\s+/)
            .filter(Boolean);

        if (words.length >= 2) {
            return (words[0][0] + words[1][0]).toUpperCase();
        }

        return label.slice(0, 2).toUpperCase();
    }

    function ensureSelection(visibleContacts) {
        const visible = Array.isArray(visibleContacts) ? visibleContacts : filterContacts();

        if (!visible.length) {
            state.selectedFp = "";
            return;
        }

        if (!state.selectedFp || !visible.some((c) => c.subject_fingerprint === state.selectedFp)) {
            state.selectedFp = visible[0].subject_fingerprint || "";
        }
    }

    function getContactByFp(fp) {
        const clean = String(fp || "");
        return (state.contacts || []).find((x) => x.subject_fingerprint === clean) || null;
    }

    function peopleCards() {
        return Array.from(document.querySelectorAll(".peopleContactCard[data-fp]"));
    }

    function selectedCardElement() {
        const fp = state.selectedFp || "";
        return peopleCards().find((el) => el.getAttribute("data-fp") === fp) || null;
    }

    function updateSelectedCardDom() {
        const selected = state.selectedFp || "";

        for (const el of peopleCards()) {
            const isSelected = !!selected && el.getAttribute("data-fp") === selected;
            el.classList.toggle("selected", isSelected);
            el.setAttribute("aria-selected", isSelected ? "true" : "false");
        }
    }

    function setSelectedFp(fp, opts = {}) {
        const clean = String(fp || "");
        if (!clean) return;

        state.selectedFp = clean;
        updateSelectedCardDom();

        const el = selectedCardElement();
        if (!el) return;

        if (opts.focus) {
            try { el.focus({ preventScroll: true }); } catch (_) { el.focus(); }
        }

        if (opts.scroll) {
            try {
                el.scrollIntoView({ block: "nearest", inline: "nearest" });
            } catch (_) {
                el.scrollIntoView();
            }
        }
    }

    function openPersonDetails(fp) {
        const c = getContactByFp(fp || state.selectedFp);
        if (!c) return;

        setSelectedFp(c.subject_fingerprint, { focus: false, scroll: false });
        openPeopleEditor({ ...c });
    }

    function togglePersonDetails(fp) {
        const selected = String(fp || state.selectedFp || "");
        if (!selected) return;

        const editor = window.PQPeopleEditor;
        const editorOpen = !!(editor && typeof editor.isOpen === "function" && editor.isOpen());
        const editorFp = editor && typeof editor.currentFingerprint === "function"
            ? editor.currentFingerprint()
            : "";

        if (editorOpen && editorFp === selected) {
            if (typeof editor.close === "function") editor.close();
            state.detailOpenFp = "";
            return;
        }

        openPersonDetails(selected);
    }

    function gridColumnCount() {
        const cards = peopleCards();
        if (!cards.length) return 1;

        const firstTop = cards[0].offsetTop;
        const cols = cards.filter((el) => el.offsetTop === firstTop).length;

        return Math.max(1, cols || 1);
    }

    function moveSelection(delta) {
        const visible = filterContacts();
        ensureSelection(visible);
        if (!visible.length) return;

        let idx = visible.findIndex((c) => c.subject_fingerprint === state.selectedFp);
        if (idx < 0) idx = 0;

        const nextIdx = Math.max(0, Math.min(visible.length - 1, idx + delta));
        const next = visible[nextIdx];
        if (!next || !next.subject_fingerprint) return;

        setSelectedFp(next.subject_fingerprint, { focus: true, scroll: true });
    }

    function isPeopleTypingTarget(ev) {
        const t = ev && ev.target;
        if (!t || !t.closest) return false;
        return !!t.closest("input, textarea, select, button, a, [contenteditable='true']");
    }

    function handlePeopleKeydown(ev) {
        if (!document.querySelector(".peopleView")) return;

        const key = String(ev.key || "");
        const keyLower = key.toLowerCase();
        const editor = window.PQPeopleEditor;
        const editorOpen = !!(editor && typeof editor.isOpen === "function" && editor.isOpen());

        if (editorOpen && (ev.ctrlKey || ev.metaKey) && keyLower === "s") {
            ev.preventDefault();
            ev.stopPropagation();

            if (typeof editor.saveCurrent === "function") {
                editor.saveCurrent();
            }

            return;
        }

        if (isPeopleTypingTarget(ev)) return;

        if (key === "ArrowRight") {
            ev.preventDefault();
            moveSelection(1);
            return;
        }

        if (key === "ArrowLeft") {
            ev.preventDefault();
            moveSelection(-1);
            return;
        }

        if (key === "ArrowDown") {
            ev.preventDefault();
            moveSelection(gridColumnCount());
            return;
        }

        if (key === "ArrowUp") {
            ev.preventDefault();
            moveSelection(-gridColumnCount());
            return;
        }

        if (key === "Home") {
            const visible = filterContacts();
            if (visible.length) {
                ev.preventDefault();
                setSelectedFp(visible[0].subject_fingerprint, { focus: true, scroll: true });
            }
            return;
        }

        if (key === "End") {
            const visible = filterContacts();
            if (visible.length) {
                ev.preventDefault();
                setSelectedFp(visible[visible.length - 1].subject_fingerprint, { focus: true, scroll: true });
            }
            return;
        }

        if (key === "Enter") {
            ev.preventDefault();
            openPersonDetails(state.selectedFp);
            return;
        }

        if (key === " " || key === "Spacebar") {
            ev.preventDefault();
            togglePersonDetails(state.selectedFp);
        }
    }

    function installPeopleKeyboard() {
        if (peopleKeyboardInstalled) return;
        peopleKeyboardInstalled = true;
        document.addEventListener("keydown", handlePeopleKeydown, true);
    }


    function renderContactCard(c) {
        const fp = c.subject_fingerprint || "";
        const isNew = isRecentlyAddedPerson(fp);
        const selected = !!fp && fp === state.selectedFp;
        const label = contactLabel(c) || shortFp(fp);
        const initials = contactInitials(c);

        const note = c.notes ? `
            <div class="mini peopleCardNotes">${esc(c.notes)}</div>
        ` : "";

        const displayNameLine = contactDisplayNameLine(c);
        const displayNameHtml = displayNameLine ? `
            <div class="mini peopleCardNickname">${esc(tr("people.name_line", { name: displayNameLine }, `Name: ${displayNameLine}`))}</div>
        ` : "";

        return `
            <div class="card peopleContactCard${selected ? " selected" : ""}"
                 style="padding:14px;"
                 data-fp="${esc(fp)}"
                 tabindex="0"
                 role="button"
                 aria-selected="${selected ? "true" : "false"}"
                 aria-label="${esc(tr("people.open_person", { name: label }, `Open person ${label}`))}">
                <div class="peopleCardMain">
                    <div class="peopleAvatar" aria-hidden="true">${esc(initials)}</div>

                    <div class="peopleCardText">
                        <div class="peopleCardTop">
                            <h3 title="${esc(label)}">
                                ${esc(label)}
                                ${isNew ? `<span class="peopleNewPill">${esc(tr("people.new", null, "new"))}</span>` : ''}
                            </h3>

                            <div class="peopleCardActions">
                                <button class="btn secondary peopleEditBtn" type="button" data-fp="${esc(fp)}">${esc(tr("people.edit", null, "Edit"))}</button>
                                <button class="btn secondary peopleDeleteBtn" type="button" data-fp="${esc(fp)}" data-label="${esc(label)}" title="${esc(tr("people.delete_title_attr", null, "Delete"))}">${esc(tr("people.delete_short", null, "Del"))}</button>
                            </div>
                        </div>

                        <div class="mini peopleCardKind">
                            ${esc(kindLabel(c.subject_kind))}
                            <span class="mono" title="${esc(fp)}">${esc(c.subject_fingerprint_short || shortFp(fp))}</span>
                        </div>

                        ${displayNameHtml}
                        ${note}
                    </div>
                </div>
            </div>
        `;
    }

    function renderContactsList() {
        if (state.loading) {
            return `
                <div class="card" style="padding:16px; margin-top:12px;">
                    <div class="mini">${esc(tr("people.loading", null, "Loading people…"))}</div>
                </div>
            `;
        }

        if (state.error) {
            return `
                <div class="card" style="padding:16px; margin-top:12px; border-color:rgba(var(--fail-rgb),0.45);">
                    <h3 style="margin:0 0 8px 0;">${esc(tr("people.unavailable", null, "People unavailable"))}</h3>
                    <div class="mini">${esc(state.error)}</div>
                </div>
            `;
        }

        const contacts = filterContacts();
        ensureSelection(contacts);

        if (!state.contacts.length) {
            return `
                <div class="card" style="padding:16px; margin-top:12px;">
                    <h3 style="margin:0 0 8px 0; font-size:17px;">${esc(tr("people.no_saved_title", null, "No people saved yet"))}</h3>
                    <div class="mini" style="line-height:1.55;">
                        ${esc(tr("people.no_saved_desc", null, "Add your first fingerprint label. Later, workspace members and external invite flows can offer “Add to People” automatically."))}
                    </div>
                </div>
            `;
        }

        if (!contacts.length) {
            return `
                <div class="card" style="padding:16px; margin-top:12px;">
                    <div class="mini">${esc(tr("people.no_search", null, "No people match this search."))}</div>
                </div>
            `;
        }

        return `
            <div class="peopleContactsList" style="display:grid; gap:10px; margin-top:12px;">
                ${contacts.map(renderContactCard).join("")}
            </div>
        `;
    }

    function draw() {
        const homeBlurb = state.ctx && state.ctx.homeBlurb;
        if (!homeBlurb) return;

        const notice = state.notice ? `
            <div class="card" style="padding:12px; margin-top:12px; border-color:${state.noticeKind === "err" ? "rgba(var(--fail-rgb),0.45)" : "rgba(var(--ok-rgb),0.35)"};">
                <div class="mini">${esc(state.notice)}</div>
            </div>
        ` : "";

        homeBlurb.innerHTML = `
            <div class="peopleView">
            <div class="card peopleHeroCard" style="padding:18px; margin-top:12px;">
                <div style="display:flex; align-items:flex-start; justify-content:space-between; gap:14px; flex-wrap:wrap;">
                    <div>
                        <h3 style="margin:0 0 8px 0; font-size:20px;">${esc(tr("people.title", null, "People"))}</h3>
                        <div class="mini" style="line-height:1.55; max-width:760px;">
                            ${esc(tr("people.hero_desc", null, "Save friendly names for DNA fingerprints, local users, external DNA Connect members, and workspace collaborators. These names are private to you and do not rename anyone globally."))}
                        </div>
                    </div>
                    <div style="display:flex; gap:10px; flex-wrap:wrap;">
                        <button class="btn secondary" id="peopleRefreshBtn" type="button">${esc(tr("people.refresh", null, "Refresh"))}</button>
                        <button class="btn" id="peopleAddBtn" type="button">${esc(tr("people.add_person", null, "Add person"))}</button>
                    </div>
                </div>

                <div style="display:flex; gap:10px; align-items:center; flex-wrap:wrap; margin-top:14px;">
                    <input id="peopleSearch" type="search" value="${esc(state.search)}"
                           placeholder="${esc(tr("people.search_placeholder", null, "Search people, notes, fingerprints…"))}"
                           style="min-width:min(420px,100%);">
                    <div class="mini">${esc(tr("people.saved_count", { count: state.contacts.length }, `${state.contacts.length} saved`))}</div>
                </div>
            </div>

            ${notice}
            ${window.PQPeopleEditor ? "" : renderEditor()}
            ${renderContactsList()}

            <div class="card peopleFutureCard" style="padding:16px; margin-top:12px;">
                <h3 style="margin:0 0 8px 0; font-size:17px;">${esc(tr("people.future_title", null, "Future use"))}</h3>
                <div class="mini" style="line-height:1.6;">
                    ${esc(tr("people.future_desc", null, "These labels will later appear in @mentions, file locks, comments, activity timelines, “what changed?” digests, and access maps."))}
                </div>
            </div>
            </div>
        `;

        bindEvents();
    }

    function bindEvents() {
        const addBtn = document.getElementById("peopleAddBtn");
        if (addBtn) addBtn.addEventListener("click", beginAdd);

        const refreshBtn = document.getElementById("peopleRefreshBtn");
        if (refreshBtn) refreshBtn.addEventListener("click", loadContacts);

        const search = document.getElementById("peopleSearch");
        if (search) {
            search.addEventListener("input", () => {
                state.search = search.value || "";
                draw();
                const next = document.getElementById("peopleSearch");
                if (next) {
                    next.focus();
                    const len = next.value.length;
                    try { next.setSelectionRange(len, len); } catch (_) {}
                }
            });
        }

        const form = document.getElementById("peopleEditForm");
        if (form) form.addEventListener("submit", saveContactFromForm);

        const cancel = document.getElementById("peopleCancelEdit");
        if (cancel) {
            cancel.addEventListener("click", () => {
                state.editing = null;
                state.notice = "";
                draw();
            });
        }

        for (const card of document.querySelectorAll(".peopleContactCard[data-fp]")) {
            card.addEventListener("click", (ev) => {
                if (ev.target && ev.target.closest && ev.target.closest(".peopleCardActions, button, a")) return;

                const fp = card.getAttribute("data-fp") || "";
                if (!fp) return;

                setSelectedFp(fp, { focus: true, scroll: false });
            });

            card.addEventListener("dblclick", (ev) => {
                if (ev.target && ev.target.closest && ev.target.closest(".peopleCardActions, button, a")) return;

                const fp = card.getAttribute("data-fp") || "";
                if (!fp) return;

                setSelectedFp(fp, { focus: true, scroll: false });
                openPersonDetails(fp);
            });

            card.addEventListener("focus", () => {
                const fp = card.getAttribute("data-fp") || "";
                if (fp) setSelectedFp(fp, { focus: false, scroll: false });
            });
        }

        for (const btn of document.querySelectorAll(".peopleEditBtn")) {
            btn.addEventListener("click", (ev) => {
                ev.preventDefault();
                ev.stopPropagation();
                beginEdit(btn.getAttribute("data-fp") || "");
            });
        }

        for (const btn of document.querySelectorAll(".peopleDeleteBtn")) {
            btn.addEventListener("click", (ev) => {
                ev.preventDefault();
                ev.stopPropagation();
                deleteContact(btn.getAttribute("data-fp") || "", btn.getAttribute("data-label") || "");
            });
        }
    }

    function render(ctx) {
        state.ctx = ctx || state.ctx;
        state.notice = (ctx && ctx.messageText) || state.notice || "";
        state.noticeKind = (ctx && ctx.messageKind) || state.noticeKind || "ok";

        installPeopleKeyboard();
        draw();
        loadContacts();
    }

    window.PQPeople = {
        render,
        reload: loadContacts
    };
})();
