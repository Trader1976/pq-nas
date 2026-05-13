/* apps/bundled/filemgr/src/www/filemgr_people.js
 * File Manager ↔ People integration.
 *
 * Keeps People/contact UI helpers out of filemgr_workspaces.js.
 */
(function () {
    "use strict";

    function shortFp(fp) {
        const s = String(fp || "");
        if (s.length <= 16) return s;
        return `${s.slice(0, 8)}…${s.slice(-6)}`;
    }

    function normalizeFingerprint(s) {
        return String(s || "")
            .trim()
            .replace(/[\s:-]+/g, "")
            .toLowerCase();
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

    function memberDefaultName(member, fp) {
        const name = String(
            member && (
                member.name ||
                member.display_name ||
                member.email ||
                member.label ||
                ""
            ) || ""
        ).trim();

        return name || shortFp(fp);
    }

    function memberKind(member) {
        const raw = String(
            member && (
                member.member_kind ||
                member.kind ||
                member.type ||
                ""
            ) || ""
        ).toLowerCase();

        if (raw === "external" || raw === "external_dna") return "external_dna";
        return "local_user";
    }

    function setStatus(statusEl, text) {
        if (statusEl) statusEl.textContent = text;
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

    function markRecentlyAddedPerson(fp) {
        const clean = normalizeFingerprint(fp);
        if (!clean) return;

        const now = Date.now();
        const obj = readRecentlyAddedPeople();

        for (const [k, v] of Object.entries(obj)) {
            if (!Number.isFinite(Number(v)) || now - Number(v) > PEOPLE_RECENT_TTL_MS) {
                delete obj[k];
            }
        }

        obj[clean] = now;
        writeRecentlyAddedPeople(obj);
    }

    function applyResolvedPeopleLabel(row, person) {
        if (!row || !person) return;

        const displayName = String(person.display_name || "").trim();
        if (!displayName) return;

        const title = row.querySelector(".workspaceMemberTitle");
        if (title) {
            if (!title.dataset.originalTitle) {
                title.dataset.originalTitle = String(title.textContent || "");
            }
            title.textContent = displayName;
            title.title = title.dataset.originalTitle && title.dataset.originalTitle !== displayName
                ? `Workspace label: ${title.dataset.originalTitle}`
                : displayName;
        }

        const duplicateLine = row.querySelector(".fmPeopleLabelLine");
        if (duplicateLine) duplicateLine.remove();
    }


    async function resolvePerson(fp) {
        const q = encodeURIComponent(fp);
        return await apiJson(`/api/v4/people/resolve?fingerprint=${q}`);
    }

    async function savePerson(payload) {
        return await apiJson("/api/v4/people/upsert", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        });
    }


    function openPeopleEditModal(opts = {}) {
        return new Promise((resolve) => {
            const options = opts || {};

            const modal = document.createElement("div");
            modal.className = "modal show";
            modal.setAttribute("role", "dialog");
            modal.setAttribute("aria-modal", "true");

            const card = document.createElement("div");
            card.className = "modalCard";
            card.style.width = "min(640px, calc(100vw - 24px))";

            const head = document.createElement("div");
            head.className = "modalHead";

            const headText = document.createElement("div");

            const title = document.createElement("div");
            title.className = "modalTitle";
            title.textContent = options.title || "Edit People";

            const sub = document.createElement("div");
            sub.className = "modalSub";
            sub.textContent = options.subtitle || "";

            headText.appendChild(title);
            if (sub.textContent) headText.appendChild(sub);
            head.appendChild(headText);

            const body = document.createElement("div");
            body.className = "modalBody";
            body.style.gridTemplateColumns = "140px 1fr";

            const nameLabel = document.createElement("div");
            nameLabel.className = "k";
            nameLabel.textContent = "Display name";

            const nameWrap = document.createElement("div");

            const nameInput = document.createElement("input");
            nameInput.type = "text";
            nameInput.value = options.displayName || "";
            nameInput.autocomplete = "off";
            nameInput.spellcheck = false;
            nameInput.style.width = "100%";
            nameInput.style.padding = "10px 12px";
            nameInput.style.borderRadius = "12px";
            nameInput.style.border = "1px solid var(--border2)";
            nameInput.style.background = "rgba(0,0,0,0.22)";
            nameInput.style.color = "var(--fg)";
            nameInput.style.font = "inherit";

            nameWrap.appendChild(nameInput);

            const fpLabel = document.createElement("div");
            fpLabel.className = "k";
            fpLabel.textContent = "Fingerprint";

            const fpValue = document.createElement("div");
            fpValue.className = "v mono";
            fpValue.textContent = options.fingerprint || "";

            const notesLabel = document.createElement("div");
            notesLabel.className = "k";
            notesLabel.textContent = "Private notes";

            const notesWrap = document.createElement("div");

            const notesInput = document.createElement("textarea");
            notesInput.value = options.notes || "";
            notesInput.placeholder = "Optional notes visible only in your People list";
            notesInput.style.width = "100%";
            notesInput.style.minHeight = "110px";
            notesInput.style.resize = "vertical";
            notesInput.style.padding = "10px 12px";
            notesInput.style.borderRadius = "12px";
            notesInput.style.border = "1px solid var(--border2)";
            notesInput.style.background = "rgba(0,0,0,0.22)";
            notesInput.style.color = "var(--fg)";
            notesInput.style.font = "inherit";
            notesInput.style.lineHeight = "1.4";

            notesWrap.appendChild(notesInput);

            const err = document.createElement("div");
            err.className = "v";
            err.style.display = "none";
            err.style.gridColumn = "1 / -1";
            err.style.padding = "8px 10px";
            err.style.border = "1px solid rgba(var(--fail-rgb),0.35)";
            err.style.borderRadius = "12px";
            err.style.background = "rgba(var(--fail-rgb),0.10)";
            err.style.color = "var(--fg)";
            err.style.fontWeight = "850";

            body.appendChild(nameLabel);
            body.appendChild(nameWrap);
            body.appendChild(fpLabel);
            body.appendChild(fpValue);
            body.appendChild(notesLabel);
            body.appendChild(notesWrap);
            body.appendChild(err);

            const foot = document.createElement("div");
            foot.className = "modalFoot";

            const hint = document.createElement("div");
            hint.className = "v";
            hint.style.opacity = "0.75";
            hint.style.fontSize = "12px";
            hint.textContent = "Saved only to your private People list.";

            const spacer = document.createElement("div");
            spacer.style.flex = "1 1 auto";

            const cancelBtn = document.createElement("button");
            cancelBtn.type = "button";
            cancelBtn.className = "btn secondary";
            cancelBtn.textContent = "Cancel";

            const okBtn = document.createElement("button");
            okBtn.type = "button";
            okBtn.className = "btn";
            okBtn.textContent = "Save People";

            foot.appendChild(hint);
            foot.appendChild(spacer);
            foot.appendChild(cancelBtn);
            foot.appendChild(okBtn);

            card.appendChild(head);
            card.appendChild(body);
            card.appendChild(foot);
            modal.appendChild(card);
            document.body.appendChild(modal);

            const showError = (text) => {
                err.textContent = text || "";
                err.style.display = text ? "block" : "none";
            };

            const close = (value) => {
                document.removeEventListener("keydown", onKey, true);
                modal.remove();
                resolve(value || null);
            };

            const submit = () => {
                const displayName = String(nameInput.value || "").trim();
                const notes = String(notesInput.value || "").trim();

                if (!displayName) {
                    showError("Display name is required.");
                    nameInput.focus();
                    return;
                }

                close({ displayName, notes });
            };

            const onKey = (ev) => {
                if (ev.key === "Escape") {
                    ev.preventDefault();
                    ev.stopPropagation();
                    close(null);
                    return;
                }

                if (ev.key === "Enter" && (ev.ctrlKey || ev.metaKey)) {
                    ev.preventDefault();
                    ev.stopPropagation();
                    submit();
                }
            };

            document.addEventListener("keydown", onKey, true);

            modal.addEventListener("click", (ev) => {
                if (ev.target === modal) close(null);
            });

            cancelBtn.addEventListener("click", () => close(null));
            okBtn.addEventListener("click", submit);

            window.setTimeout(() => {
                nameInput.focus();
                nameInput.select();
            }, 0);
        });
    }

    function buildPeopleControls(row, member, opts) {
        const fp = normalizeFingerprint(row.dataset.fingerprint || "");
        if (!fp) return;
        if (row.querySelector(".fmPeopleControls")) return;

        const statusEl = opts && opts.statusEl;
        const workspaceName = String(opts && opts.workspaceName || "").trim();

        const wrap = document.createElement("div");
        wrap.className = "fmPeopleControls";
        wrap.style.display = "flex";
        wrap.style.gap = "8px";
        wrap.style.alignItems = "center";
        wrap.style.flexWrap = "wrap";
        wrap.style.paddingTop = "8px";
        wrap.style.borderTop = "1px solid rgba(var(--fg-rgb),0.10)";

        const btn = document.createElement("button");
        btn.className = "btn secondary";
        btn.type = "button";
        btn.textContent = "People…";
        btn.disabled = true;

        const hint = document.createElement("span");
        hint.className = "mono";
        hint.style.opacity = ".76";
        hint.style.fontSize = "12px";
        hint.textContent = "Checking People…";

        wrap.appendChild(btn);
        wrap.appendChild(hint);
        row.appendChild(wrap);

        resolvePerson(fp).then((j) => {
            const person = j && j.person ? j.person : {};
            const resolved = !!(j && j.resolved);

            const existingName = String(person.display_name || "").trim();
            const fallbackName = memberDefaultName(member, fp);
            const currentName = existingName || fallbackName;

            if (resolved) {
                applyResolvedPeopleLabel(row, person);
            }

            btn.disabled = false;
            btn.textContent = resolved ? "Edit People" : "Add to People";
            hint.textContent = resolved
                ? "Saved in People"
                : "Not saved in People";

            btn.addEventListener("click", async () => {
                const defaultNotes = String(person.notes || "").trim() ||
                    (workspaceName ? `Workspace collaborator: ${workspaceName}` : "");

                const picked = await openPeopleEditModal({
                    title: resolved ? "Edit People" : "Add to People",
                    subtitle: "Save a private name and notes for this workspace member.",
                    displayName: currentName,
                    notes: defaultNotes,
                    fingerprint: fp
                });
                if (!picked) return;

                const displayName = picked.displayName;
                const notesPrompt = picked.notes;

                const old = btn.textContent;
                btn.disabled = true;
                btn.textContent = "Saving…";
                hint.textContent = "Saving People label…";

                try {
                    const saved = await savePerson({
                        subject_fingerprint: fp,
                        subject_kind: memberKind(member),
                        display_name: displayName,
                        nickname: String(person.nickname || ""),
                        notes: String(notesPrompt || "").trim()
                    });

                    const savedPerson = saved && saved.contact ? saved.contact : { display_name: displayName };
                    const savedName = String(savedPerson.display_name || displayName);

                    markRecentlyAddedPerson(savedPerson.subject_fingerprint || fp);

                    applyResolvedPeopleLabel(row, savedPerson);

                    btn.textContent = "Edit People";
                    hint.textContent = "Saved in People";
                    setStatus(statusEl, `Saved ${savedName} in People.`);
                } catch (e) {
                    btn.textContent = old;
                    hint.textContent = resolved
                        ? "Saved in People"
                        : "Not saved in People";
                    setStatus(statusEl, `People save failed: ${String(e && e.message ? e.message : e)}`);
                } finally {
                    btn.disabled = false;
                }
            });
        }).catch((e) => {
            btn.disabled = false;
            btn.textContent = "Add to People";
            hint.textContent = "People lookup unavailable";

            btn.addEventListener("click", () => {
                setStatus(statusEl, `People lookup failed: ${String(e && e.message ? e.message : e)}`);
            });
        });
    }

    function enhanceWorkspaceMembers(opts = {}) {
        const listEl = opts.listEl || document.getElementById("workspaceMembersList");
        if (!listEl) return;

        const members = Array.isArray(opts.members) ? opts.members : [];
        const byFp = new Map();

        for (const m of members) {
            const fp = normalizeFingerprint(m && m.fingerprint || "");
            if (fp) byFp.set(fp, m);
        }

        for (const row of listEl.querySelectorAll(".memberRow[data-fingerprint]")) {
            const fp = normalizeFingerprint(row.dataset.fingerprint || "");
            buildPeopleControls(row, byFp.get(fp) || null, opts);
        }
    }

    window.FMPeople = {
        enhanceWorkspaceMembers
    };
})();
