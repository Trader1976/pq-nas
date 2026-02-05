Android 7 TLS Compatibility

Some Android 7.x devices may fail to connect directly to PQ-NAS over HTTPS when nginx terminates TLS using Let’s Encrypt certificates.

This is caused by outdated CA trust stores on older Android releases and differences in certificate chain delivery.

The same devices typically work when PQ-NAS is accessed through Cloudflare, which presents legacy-compatible certificate chains.

PQ-NAS does not weaken TLS verification or install custom root certificates inside the application.

For reliable mobile access, PQ-NAS recommends:

Android 8+ devices, or

placing Cloudflare (or another modern reverse proxy/CDN) in front of PQ-NAS.

TLS failures on older Android devices usually manifest as:
CERTIFICATE_VERIFY_FAILED: unable to get local issuer certificate
This is unrelated to QR authentication or cryptographic signature verification.