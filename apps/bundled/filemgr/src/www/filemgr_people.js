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
                const name = window.prompt(
                    "Name to show in your private People list:",
                    currentName
                );
                if (name === null) return;

                const displayName = String(name || "").trim();
                if (!displayName) {
                    setStatus(statusEl, "People save failed: display name is required.");
                    return;
                }

                const defaultNotes = String(person.notes || "").trim() ||
                    (workspaceName ? `Workspace collaborator: ${workspaceName}` : "");

                const notesPrompt = window.prompt(
                    "Private notes for this person, optional:",
                    defaultNotes
                );
                if (notesPrompt === null) return;

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
