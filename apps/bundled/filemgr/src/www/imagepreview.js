(() => {
    "use strict";

    const FM = window.PQNAS_FILEMGR;
    if (!FM) return;

    const imagePreviewModal = document.getElementById("imagePreviewModal");
    const imagePreviewCard = document.getElementById("imagePreviewCard");
    const imagePreviewHead = document.getElementById("imagePreviewHead");
    const imagePreviewClose = document.getElementById("imagePreviewClose");
    const imagePreviewTitle = document.getElementById("imagePreviewTitle");
    const imagePreviewPath = document.getElementById("imagePreviewPath");
    const imagePreviewInfo = document.getElementById("imagePreviewInfo");
    const imagePreviewImg = document.getElementById("imagePreviewImg");
    const imagePreviewFitBtn = document.getElementById("imagePreviewFitBtn");
    const imagePreviewActualBtn = document.getElementById("imagePreviewActualBtn");
    const imagePreviewPrevBtn = document.getElementById("imagePreviewPrevBtn");
    const imagePreviewNextBtn = document.getElementById("imagePreviewNextBtn");

    let state = {
        relPath: "",
        objectMode: "fit"
    };
    let dragState = {
        active: false,
        startX: 0,
        startY: 0,
        cardLeft: 0,
        cardTop: 0,
        moved: false
    };
    function isImageItem(item) {
        return !!(item &&
            item.type === "file" &&
            FM.isProbablyImagePreviewableName &&
            FM.isProbablyImagePreviewableName(item.name));
    }

    function getImageItemsInView() {
        const items = FM.getLastListedItems ? FM.getLastListedItems() : [];
        return items.filter(isImageItem);
    }

    function currentImageIndex() {
        const items = getImageItemsInView();
        const idx = items.findIndex((it) => FM.currentRelPathFor(it) === state.relPath);
        return { items, idx };
    }

    function updateNavButtons() {
        const { items, idx } = currentImageIndex();
        const hasMany = items.length > 1;
        if (imagePreviewPrevBtn) imagePreviewPrevBtn.disabled = !hasMany || idx < 0;
        if (imagePreviewNextBtn) imagePreviewNextBtn.disabled = !hasMany || idx < 0;
    }

    function openByIndex(nextIdx) {
        const { items } = currentImageIndex();
        if (!items.length) return;

        const len = items.length;
        const idx = ((nextIdx % len) + len) % len;
        openImageFor(items[idx]);
    }

    function openPrevImage() {
        const { idx } = currentImageIndex();
        if (idx < 0) return;
        openByIndex(idx - 1);
    }

    function openNextImage() {
        const { idx } = currentImageIndex();
        if (idx < 0) return;
        openByIndex(idx + 1);
    }
    function openModal() {
        if (!imagePreviewModal) return;
        imagePreviewModal.classList.add("show");
        imagePreviewModal.setAttribute("aria-hidden", "false");
    }

    function closeModal() {
        if (!imagePreviewModal) return;
        imagePreviewModal.classList.remove("show");
        imagePreviewModal.setAttribute("aria-hidden", "true");
        if (imagePreviewImg) {
            imagePreviewImg.removeAttribute("src");
            imagePreviewImg.alt = "";
        }
    }
    function clamp(n, lo, hi) {
        return Math.max(lo, Math.min(hi, n));
    }

    function placeCardCentered() {
        if (!imagePreviewCard) return;

        imagePreviewCard.style.transform = "translateX(-50%)";
        imagePreviewCard.style.left = "50%";
        imagePreviewCard.style.top = "80px";
    }

    function clampCardIntoViewport() {
        if (!imagePreviewCard) return;

        const rect = imagePreviewCard.getBoundingClientRect();
        const pad = 8;

        let left = rect.left;
        let top = rect.top;

        const maxLeft = Math.max(pad, window.innerWidth - rect.width - pad);
        const maxTop = Math.max(pad, window.innerHeight - rect.height - pad);

        left = clamp(left, pad, maxLeft);
        top = clamp(top, pad, maxTop);

        imagePreviewCard.style.transform = "none";
        imagePreviewCard.style.left = `${left}px`;
        imagePreviewCard.style.top = `${top}px`;
    }
    function applyFitMode() {
        state.objectMode = "fit";
        if (!imagePreviewImg) return;
        imagePreviewImg.style.maxWidth = "100%";
        imagePreviewImg.style.maxHeight = "100%";
        imagePreviewImg.style.width = "auto";
        imagePreviewImg.style.height = "auto";
    }

    function applyActualMode() {
        state.objectMode = "actual";
        if (!imagePreviewImg) return;
        imagePreviewImg.style.maxWidth = "none";
        imagePreviewImg.style.maxHeight = "none";
        imagePreviewImg.style.width = "auto";
        imagePreviewImg.style.height = "auto";
    }

    function openImageFor(item) {
        if (!item || item.type !== "file") return;

        const rel = FM.currentRelPathFor(item);
        const src = `/api/v4/files/get?path=${encodeURIComponent(rel)}`;

        state.relPath = rel;

        if (imagePreviewTitle) imagePreviewTitle.textContent = "Image preview";
        if (imagePreviewPath) imagePreviewPath.textContent = "/" + rel;
        if (imagePreviewInfo) imagePreviewInfo.textContent = "Loading…";

        if (imagePreviewImg) {
            imagePreviewImg.alt = item.name || "image";
            imagePreviewImg.onload = () => {
                if (imagePreviewInfo) {
                    const { items, idx } = currentImageIndex();
                    const pos = (idx >= 0 && items.length > 1) ? ` • ${idx + 1} / ${items.length}` : "";
                    imagePreviewInfo.textContent = `${imagePreviewImg.naturalWidth} × ${imagePreviewImg.naturalHeight}${pos}`;
                }
                updateNavButtons();
            };
            imagePreviewImg.onerror = () => {
                if (imagePreviewInfo) imagePreviewInfo.textContent = "Failed to load preview";
            };
            imagePreviewImg.src = src;
        }

        applyFitMode();
        placeCardCentered();
        openModal();
        updateNavButtons();

    }

    imagePreviewClose?.addEventListener("click", closeModal);

    imagePreviewModal?.addEventListener("click", (e) => {
        if (dragState.moved) {
            dragState.moved = false;
            return;
        }
        if (e.target === imagePreviewModal) closeModal();
    });

    imagePreviewFitBtn?.addEventListener("click", applyFitMode);
    imagePreviewActualBtn?.addEventListener("click", applyActualMode);
    imagePreviewPrevBtn?.addEventListener("click", openPrevImage);
    imagePreviewNextBtn?.addEventListener("click", openNextImage);

    document.addEventListener("keydown", (e) => {
        if (!imagePreviewModal || !imagePreviewModal.classList.contains("show")) return;

        if (e.key === "Escape") {
            e.preventDefault();
            closeModal();
            return;
        }

        if (e.key === "ArrowLeft") {
            e.preventDefault();
            openPrevImage();
            return;
        }

        if (e.key === "ArrowRight") {
            e.preventDefault();
            openNextImage();
        }
    });
    imagePreviewHead?.addEventListener("pointerdown", (e) => {
        if (!imagePreviewCard) return;
        if (e.target && e.target.closest && e.target.closest("button")) return;

        const rect = imagePreviewCard.getBoundingClientRect();

        dragState.active = true;
        dragState.startX = e.clientX;
        dragState.startY = e.clientY;
        dragState.cardLeft = rect.left;
        dragState.cardTop = rect.top;
        dragState.moved = false;

        imagePreviewCard.style.transform = "none";
        imagePreviewCard.style.left = `${rect.left}px`;
        imagePreviewCard.style.top = `${rect.top}px`;

        try { imagePreviewHead.setPointerCapture(e.pointerId); } catch (_) {}
        e.preventDefault();
    });

    imagePreviewHead?.addEventListener("pointermove", (e) => {
        if (!dragState.active || !imagePreviewCard) return;

        const dx = e.clientX - dragState.startX;
        const dy = e.clientY - dragState.startY;

        if (Math.abs(dx) > 2 || Math.abs(dy) > 2) dragState.moved = true;

        const rect = imagePreviewCard.getBoundingClientRect();
        const pad = 8;

        const nextLeft = clamp(
            dragState.cardLeft + dx,
            pad,
            Math.max(pad, window.innerWidth - rect.width - pad)
        );

        const nextTop = clamp(
            dragState.cardTop + dy,
            pad,
            Math.max(pad, window.innerHeight - rect.height - pad)
        );

        imagePreviewCard.style.left = `${nextLeft}px`;
        imagePreviewCard.style.top = `${nextTop}px`;
    });

    function endDrag() {
        dragState.active = false;
    }

    imagePreviewHead?.addEventListener("pointerup", endDrag);
    imagePreviewHead?.addEventListener("pointercancel", endDrag);

    window.addEventListener("resize", () => {
        if (imagePreviewModal && imagePreviewModal.classList.contains("show")) {
            clampCardIntoViewport();
        }
    });
    FM.imagePreview = {
        open: openImageFor
    };
})();