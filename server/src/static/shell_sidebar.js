(() => {
    "use strict";

    const KEY = "pqnas_sidebar_collapsed_v1";

    function labelFor(el) {
        if (!el) return "";
        const first = el.querySelector("span:not(.k):not(.navAlertBadge)");
        const text = (first ? first.textContent : el.textContent || "").trim();
        return text.replace(/\s+/g, " ");
    }

    function setTooltips(sidebar) {
        for (const el of sidebar.querySelectorAll(".navbtn")) {
            const label = labelFor(el);
            if (label && !el.getAttribute("title")) {
                el.setAttribute("title", label);
            }
        }
    }

    function apply(collapsed) {
        document.body.classList.toggle("shellSidebarCollapsed", !!collapsed);

        const desktop = document.querySelector(".desktop");
        if (desktop) desktop.classList.toggle("shellSidebarCollapsed", !!collapsed);

        const btn = document.getElementById("sidebarCollapseBtn");
        if (btn) {
            btn.textContent = collapsed ? "›" : "‹";
            btn.title = collapsed ? "Expand sidebar" : "Collapse sidebar";
            btn.setAttribute("aria-label", btn.title);
            btn.setAttribute("aria-pressed", collapsed ? "true" : "false");
        }
    }

    function init() {
        const sidebar = document.querySelector(".sidebar");
        if (!sidebar) return;

        setTooltips(sidebar);

        let btn = document.getElementById("sidebarCollapseBtn");
        if (!btn) {
            btn = document.createElement("button");
            btn.id = "sidebarCollapseBtn";
            btn.className = "sidebarCollapseBtn";
            btn.type = "button";
            sidebar.appendChild(btn);
        }

        const collapsed = localStorage.getItem(KEY) === "1";
        apply(collapsed);

        btn.addEventListener("click", () => {
            const next = !document.body.classList.contains("shellSidebarCollapsed");
            localStorage.setItem(KEY, next ? "1" : "0");
            apply(next);
        });
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", init, { once: true });
    } else {
        init();
    }
})();
