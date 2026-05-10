(() => {
    "use strict";

    const STYLE_ID = "externalWorkspaceTopbarStyle";

    function injectStyles() {
        if (document.getElementById(STYLE_ID)) return;

        const style = document.createElement("style");
        style.id = STYLE_ID;
        style.textContent = `
            #fileSurface > .cardHead{
                padding-bottom:12px;
            }

            .externalWorkspaceTopbar{
                display:flex;
                align-items:center;
                justify-content:space-between;
                gap:18px;
                width:100%;
                min-width:0;
            }

            .externalWorkspaceTopbarLeft{
                min-width:220px;
                flex:1 1 auto;
            }

            .externalWorkspaceTopbarLeft h1{
                margin:0 0 6px;
                line-height:1.1;
            }

            .externalWorkspaceTopbarLeft .sub{
                margin:0;
            }

            .externalWorkspaceTopbarRight{
                display:flex;
                align-items:center;
                justify-content:flex-end;
                gap:10px;
                flex:0 0 auto;
                margin-left:auto;
                flex-wrap:wrap;
            }

            .externalWorkspaceTopbarRight .pill{
                white-space:nowrap;
            }

            .externalWorkspaceTopbarRight .fileToolbarMain{
                display:flex;
                align-items:center;
                justify-content:flex-end;
                gap:10px;
                flex-wrap:wrap;
            }

            .externalWorkspaceTopbarRight .toolbarBadge{
                margin-right:0;
            }

            #fileSurface .toolbar.externalToolbarMoved{
                display:none;
            }

            #fileSurface .cardBody{
                padding-top:12px;
            }

            @media (max-width:900px){
                .externalWorkspaceTopbar{
                    align-items:flex-start;
                    flex-direction:column;
                }

                .externalWorkspaceTopbarRight{
                    justify-content:flex-start;
                    margin-left:0;
                    width:100%;
                }
            }
        `;
        document.head.appendChild(style);
    }

    function installTopbar() {
        const fileSurface = document.getElementById("fileSurface");
        if (!fileSurface) return;

        const head = fileSurface.querySelector(":scope > .cardHead");
        const toolbar = fileSurface.querySelector(".toolbar");
        const mainTools = fileSurface.querySelector(".fileToolbarMain");
        const accessPill = document.getElementById("accessPill");
        const h1 = head ? head.querySelector("h1") : null;
        const fileSub = document.getElementById("fileSub");

        if (!head || !toolbar || !mainTools || !accessPill || !h1 || !fileSub) return;
        if (document.getElementById("externalWorkspaceTopbar")) return;

        injectStyles();

        const topLine = head.querySelector(".topLine");

        const topbar = document.createElement("div");
        topbar.id = "externalWorkspaceTopbar";
        topbar.className = "externalWorkspaceTopbar";

        const left = document.createElement("div");
        left.className = "externalWorkspaceTopbarLeft";

        const right = document.createElement("div");
        right.className = "externalWorkspaceTopbarRight";

        left.appendChild(h1);
        left.appendChild(fileSub);

        right.appendChild(accessPill);
        right.appendChild(mainTools);

        topbar.appendChild(left);
        topbar.appendChild(right);

        if (topLine) {
            topLine.replaceWith(topbar);
        } else {
            head.prepend(topbar);
        }

        toolbar.classList.add("externalToolbarMoved");
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", installTopbar, { once:true });
    } else {
        installTopbar();
    }
})();
