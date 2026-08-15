#!/usr/bin/env python3
"""Shared TLS helper: a verify-ON context that works on a bare python.org install.

A stock python.org macOS build ships an ``openssl_cafile`` path that does not exist, so
``urllib.request.urlopen`` fails every HTTPS request with CERTIFICATE_VERIFY_FAILED — which a
first-time user sees as "the webhook tool is broken". The fix is not to disable verification
(verify-off would let a MITM feed the brain fake advisories); it is to load ``certifi``'s CA
bundle **only when the default store turned out to be empty**. A machine with a real system
store (Linux, Homebrew python, or a corporate proxy CA installed) keeps its own trust roots.

Used by tools that talk to non-target HTTPS endpoints: notify.py (webhooks) and techwatch.py
(OSV, CISA KEV). Import as a module; there is no CLI.
"""
import ssl


def ssl_context():
    """A verifying SSLContext, falling back to certifi when the default store is empty."""
    ctx = ssl.create_default_context()
    try:
        if not ctx.cert_store_stats().get("x509_ca"):
            import certifi
            ctx = ssl.create_default_context(cafile=certifi.where())
    except Exception:
        pass          # keep the default context; the caller's error stays a loud failure
    return ctx
