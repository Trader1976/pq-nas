/* server/src/static/people.js
 * DNA-Nexus People UI
 *
 * Private per-user friendly names for fingerprints, workspace collaborators,
 * external DNA Connect members, and future @mentions/locks/activity/access maps.
 */
(function () {
    "use strict";

    const state = {
        ctx: null,
        contacts: [],
        loading: false,
        error: "",
        notice: "",
        noticeKind: "ok",
        editing: null,
        search: ""
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
        if (kind === "local_user") return "Local user";
        if (kind === "external_dna") return "External DNA";
        return "Fingerprint";
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
            throw new Error(`Unexpected response from ${path}`);
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
            state.notice = "Fingerprint is required.";
            state.noticeKind = "err";
            draw();
            return;
        }

        if (!displayName) {
            state.notice = "Display name is required.";
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
            state.notice = "Person saved.";
            state.noticeKind = "ok";
            await loadContacts();
        } catch (e) {
            state.notice = `Save failed: ${String(e && e.message ? e.message : e)}`;
            state.noticeKind = "err";
            draw();
        }
    }

    async function deleteContact(fp, label) {
        const ok = window.confirm(`Remove "${label || shortFp(fp)}" from your People list?`);
        if (!ok) return;

        try {
            await apiJson("/api/v4/people/delete", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ subject_fingerprint: fp })
            });

            state.notice = "Person removed.";
            state.noticeKind = "ok";
            await loadContacts();
        } catch (e) {
            state.notice = `Delete failed: ${String(e && e.message ? e.message : e)}`;
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

        editor.open(c, {
            onSaved: async () => {
                state.notice = "Person saved.";
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
        openPeopleEditor({ ...c });
    }

    function renderEditor() {
        const c = state.editing;
        if (!c) return "";

        const isExisting = !!c.subject_fingerprint;

        return `
            <div class="card" style="padding:16px; margin-top:12px; border-color:rgba(var(--accent-rgb),0.35);">
                <h3 style="margin:0 0 8px 0; font-size:17px;">${isExisting ? "Edit person" : "Add person"}</h3>
                <div class="mini" style="line-height:1.5; margin-bottom:12px;">
                    This only changes your private label for this fingerprint. It does not rename the real user globally.
                </div>

                <form id="peopleEditForm">
                    <div style="display:grid; grid-template-columns:repeat(auto-fit,minmax(240px,1fr)); gap:12px;">
                        <label class="mini" style="display:flex; flex-direction:column; gap:6px;">
                            Display name
                            <input id="peopleDisplayName" type="text" maxlength="120" required
                                   value="${esc(c.display_name || "")}"
                                   placeholder="Leo">
                        </label>

                        <label class="mini" style="display:flex; flex-direction:column; gap:6px;">
                            Type
                            <select id="peopleKind">
                                <option value="fingerprint" ${c.subject_kind === "fingerprint" ? "selected" : ""}>Fingerprint</option>
                                <option value="external_dna" ${c.subject_kind === "external_dna" ? "selected" : ""}>External DNA</option>
                                <option value="local_user" ${c.subject_kind === "local_user" ? "selected" : ""}>Local user</option>
                            </select>
                        </label>

                        <label class="mini" style="display:flex; flex-direction:column; gap:6px;">
                            Nickname
                            <input id="peopleNickname" type="text" maxlength="120"
                                   value="${esc(c.nickname || "")}"
                                   placeholder="Optional">
                        </label>
                    </div>

                    <label class="mini" style="display:flex; flex-direction:column; gap:6px; margin-top:12px;">
                        Fingerprint
                        <input id="peopleFingerprint" type="text" required ${isExisting ? "readonly" : ""}
                               value="${esc(c.subject_fingerprint || "")}"
                               placeholder="hex fingerprint">
                    </label>

                    <label class="mini" style="display:flex; flex-direction:column; gap:6px; margin-top:12px;">
                        Notes
                        <textarea id="peopleNotes" maxlength="2000" rows="4"
                                  placeholder="Private note, e.g. John from motorbike club">${esc(c.notes || "")}</textarea>
                    </label>

                    <div style="display:flex; gap:10px; flex-wrap:wrap; margin-top:14px;">
                        <button class="btn" type="submit">Save</button>
                        <button class="btn secondary" id="peopleCancelEdit" type="button">Cancel</button>
                    </div>
                </form>
            </div>
        `;
    }

    function renderContactCard(c) {
        const fp = c.subject_fingerprint || "";
        const isNew = isRecentlyAddedPerson(fp);
        const label = c.display_name || shortFp(fp);
        const note = c.notes ? `
            <div class="mini" style="line-height:1.45; margin-top:8px;">${esc(c.notes)}</div>
        ` : "";

        const nick = c.nickname ? `
            <div class="mini" style="margin-top:4px;">Nickname: ${esc(c.nickname)}</div>
        ` : "";

        return `
            <div class="card peopleContactCard" style="padding:14px;">
                <div style="display:flex; align-items:flex-start; justify-content:space-between; gap:12px;">
                    <div style="min-width:0;">
                        <h3 style="margin:0; font-size:17px;">
                            ${esc(label)}
                            ${isNew ? '<span class="peopleNewPill">new</span>' : ''}
                        </h3>
                        <div class="mini" style="margin-top:5px;">
                            ${esc(kindLabel(c.subject_kind))}
                            <span class="mono" title="${esc(fp)}" style="margin-left:8px;">${esc(c.subject_fingerprint_short || shortFp(fp))}</span>
                        </div>
                        ${nick}
                        ${note}
                    </div>

                    <div style="display:flex; gap:8px; flex-wrap:wrap; justify-content:flex-end;">
                        <button class="btn secondary peopleEditBtn" type="button" data-fp="${esc(fp)}">Edit</button>
                        <button class="btn secondary peopleDeleteBtn" type="button" data-fp="${esc(fp)}" data-label="${esc(label)}">Delete</button>
                    </div>
                </div>
            </div>
        `;
    }

    function renderContactsList() {
        if (state.loading) {
            return `
                <div class="card" style="padding:16px; margin-top:12px;">
                    <div class="mini">Loading people…</div>
                </div>
            `;
        }

        if (state.error) {
            return `
                <div class="card" style="padding:16px; margin-top:12px; border-color:rgba(var(--fail-rgb),0.45);">
                    <h3 style="margin:0 0 8px 0;">People unavailable</h3>
                    <div class="mini">${esc(state.error)}</div>
                </div>
            `;
        }

        const contacts = filterContacts();

        if (!state.contacts.length) {
            return `
                <div class="card" style="padding:16px; margin-top:12px;">
                    <h3 style="margin:0 0 8px 0; font-size:17px;">No people saved yet</h3>
                    <div class="mini" style="line-height:1.55;">
                        Add your first fingerprint label. Later, workspace members and external invite flows can offer
                        “Add to People” automatically.
                    </div>
                </div>
            `;
        }

        if (!contacts.length) {
            return `
                <div class="card" style="padding:16px; margin-top:12px;">
                    <div class="mini">No people match this search.</div>
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
                        <h3 style="margin:0 0 8px 0; font-size:20px;">People</h3>
                        <div class="mini" style="line-height:1.55; max-width:760px;">
                            Save friendly names for DNA fingerprints, local users, external DNA Connect members,
                            and workspace collaborators. These names are private to you and do not rename anyone globally.
                        </div>
                    </div>
                    <div style="display:flex; gap:10px; flex-wrap:wrap;">
                        <button class="btn secondary" id="peopleRefreshBtn" type="button">Refresh</button>
                        <button class="btn" id="peopleAddBtn" type="button">Add person</button>
                    </div>
                </div>

                <div style="display:flex; gap:10px; align-items:center; flex-wrap:wrap; margin-top:14px;">
                    <input id="peopleSearch" type="search" value="${esc(state.search)}"
                           placeholder="Search people, notes, fingerprints…"
                           style="min-width:min(420px,100%);">
                    <div class="mini">${state.contacts.length} saved</div>
                </div>
            </div>

            ${notice}
            ${window.PQPeopleEditor ? "" : renderEditor()}
            ${renderContactsList()}

            <div class="card peopleFutureCard" style="padding:16px; margin-top:12px;">
                <h3 style="margin:0 0 8px 0; font-size:17px;">Future use</h3>
                <div class="mini" style="line-height:1.6;">
                    These labels will later appear in @mentions, file locks, comments, activity timelines,
                    “what changed?” digests, and access maps.
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

        for (const btn of document.querySelectorAll(".peopleEditBtn")) {
            btn.addEventListener("click", () => beginEdit(btn.getAttribute("data-fp") || ""));
        }

        for (const btn of document.querySelectorAll(".peopleDeleteBtn")) {
            btn.addEventListener("click", () => {
                deleteContact(btn.getAttribute("data-fp") || "", btn.getAttribute("data-label") || "");
            });
        }
    }

    function render(ctx) {
        state.ctx = ctx || state.ctx;
        state.notice = (ctx && ctx.messageText) || state.notice || "";
        state.noticeKind = (ctx && ctx.messageKind) || state.noticeKind || "ok";

        draw();
        loadContacts();
    }

    window.PQPeople = {
        render,
        reload: loadContacts
    };
})();
