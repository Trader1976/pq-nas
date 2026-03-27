(() => {
    "use strict";

    const FM = window.PQNAS_FILEMGR;
    if (!FM) return;

    const imagePreviewModal = document.getElementById("imagePreviewModal");
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
        openModal();
        updateNavButtons();

    }

    imagePreviewClose?.addEventListener("click", closeModal);

    imagePreviewModal?.addEventListener("click", (e) => {
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

    FM.imagePreview = {
        open: openImageFor
    };
})();