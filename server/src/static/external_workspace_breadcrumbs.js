(() => {
    "use strict";

    const STYLE_ID = "externalWorkspaceBreadcrumbsStyle";

    function injectStyles() {
        if (document.getElementById(STYLE_ID)) return;

        const style = document.createElement("style");
        style.id = STYLE_ID;
        style.textContent = `
            .externalWorkspaceLocationBar{
                display:flex;
                align-items:center;
                gap:8px;
                flex-wrap:wrap;
                min-height:28px;
                padding:0;
                color:var(--fg);
                font-family:var(--sans);
            }

            .externalWorkspaceLocationBadge{
                display:inline-flex;
                align-items:center;
                justify-content:center;
                min-height:22px;
                padding:3px 12px;
                border-radius:999px;
                border:1px solid rgba(var(--accent-rgb),0.30);
                background:rgba(var(--accent-rgb),0.16);
                color:var(--muted);
                font-size:12px;
                font-weight:800;
                letter-spacing:.08em;
                text-transform:uppercase;
                line-height:1;
            }

            .externalWorkspaceLocationLabel{
                font-weight:800;
                color:var(--fg);
                opacity:.92;
            }

            .externalWorkspaceCrumbBtn{
                appearance:none;
                border:0;
                background:transparent;
                color:var(--fg);
                font:inherit;
                font-weight:800;
                padding:2px 2px;
                cursor:pointer;
                border-radius:8px;
            }

            .externalWorkspaceCrumbBtn:hover{
                color:var(--accent);
                text-decoration:underline;
            }

            .externalWorkspaceCrumbSep{
                color:var(--muted);
                opacity:.8;
                font-weight:700;
            }

            .externalWorkspaceLocationPath{
                display:flex;
                align-items:center;
                flex-wrap:wrap;
                gap:7px;
                min-width:0;
            }
        `;
        document.head.appendChild(style);
    }

    function escapeHtml(s) {
        return String(s == null ? "" : s)
            .replaceAll("&", "&amp;")
            .replaceAll("<", "&lt;")
            .replaceAll(">", "&gt;")
            .replaceAll("\"", "&quot;")
            .replaceAll("'", "&#39;");
    }

    function readCrumbs(el) {
        const buttons = Array.from(el.querySelectorAll("button[data-crumb]"));
        return buttons
            .map((btn) => ({
                path: String(btn.dataset.crumb || ""),
                label: String(btn.textContent || "").trim() || "Workspace root"
            }))
            .filter((x, idx) => idx === 0 || x.label);
    }

    function enhanceBreadcrumbs() {
        const el = document.getElementById("breadcrumbs");
        if (!el) return;

        const crumbs = readCrumbs(el);
        if (!crumbs.length) return;

        const signature = crumbs.map((x) => `${x.path}\u0000${x.label}`).join("\u0001");
        if (el.dataset.externalBreadcrumbSignature === signature) return;

        injectStyles();
        el.dataset.externalBreadcrumbSignature = signature;

        const pathHtml = crumbs.map((crumb, idx) => {
            const label = idx === 0 ? "/" : crumb.label;
            const sep = idx === 0 ? "" : `<span class="externalWorkspaceCrumbSep">›</span>`;
            return `
                ${sep}
                <button class="externalWorkspaceCrumbBtn" type="button" data-crumb="${escapeHtml(crumb.path)}">${escapeHtml(label)}</button>
            `;
        }).join("");

        el.innerHTML = `
            <div class="externalWorkspaceLocationBar">
                <span class="externalWorkspaceLocationBadge">Workspace</span>
                <span class="externalWorkspaceLocationLabel">Location</span>
                <span class="externalWorkspaceLocationPath">${pathHtml}</span>
            </div>
        `;
    }

    function start() {
        enhanceBreadcrumbs();

        const el = document.getElementById("breadcrumbs");
        if (!el || el.__externalWorkspaceBreadcrumbObserver) return;

        const observer = new MutationObserver(() => enhanceBreadcrumbs());
        observer.observe(el, { childList:true, subtree:true, characterData:true });
        el.__externalWorkspaceBreadcrumbObserver = observer;
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", start, { once:true });
    } else {
        start();
    }
})();
