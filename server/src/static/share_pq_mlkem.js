(() => {
    "use strict";

    let modPromise = null;

    function normalizeB64(s) {
        return String(s || "").replace(/-/g, "+").replace(/_/g, "/");
    }

    function b64ToBytes(b64) {
        const bin = atob(normalizeB64(b64));
        const out = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
        return out;
    }

    function bytesToB64(bytes) {
        let s = "";
        const chunk = 0x8000;
        for (let i = 0; i < bytes.length; i += chunk) {
            s += String.fromCharCode(...bytes.subarray(i, i + chunk));
        }
        return btoa(s);
    }

    async function loadMlKemModule() {
        if (!modPromise) {
            modPromise = import("/static/vendor/mlkem-wasm.js?v=1").then((m) => m?.default || m);
        }
        return modPromise;
    }

    globalThis.PqShareMlKemV1 = {
        async isAvailable() {
            try {
                const mlkem = await loadMlKemModule();
                return !!(mlkem && typeof mlkem.generateKey === "function");
            } catch {
                return false;
            }
        },

        backendName() {
            return "mlkem-wasm";
        },

        async keygen768() {
            const mlkem = await loadMlKemModule();

            const pair = await mlkem.generateKey(
                { name: "ML-KEM-768" },
                true,
                ["encapsulateBits", "decapsulateBits"]
            );

            const rawPublic = new Uint8Array(await mlkem.exportKey("raw-public", pair.publicKey));
            const rawSeed = new Uint8Array(await mlkem.exportKey("raw-seed", pair.privateKey));

            return {
                alg: "ML-KEM-768",
                public_key_b64: bytesToB64(rawPublic),
                private_key_b64: bytesToB64(rawSeed)
            };
        },

        async decapsulate768({ privateKeyB64, ciphertextB64 }) {
            const mlkem = await loadMlKemModule();

            const privateKey = await mlkem.importKey(
                "raw-seed",
                b64ToBytes(privateKeyB64),
                { name: "ML-KEM-768" },
                false,
                ["decapsulateBits"]
            );

            const shared = await mlkem.decapsulateBits(
                { name: "ML-KEM-768" },
                privateKey,
                b64ToBytes(ciphertextB64)
            );

            return new Uint8Array(shared);
        }
    };
})();