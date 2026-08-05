# Pack 04 — Public OAuth and mTLS

## Objective

Validate PSMatrix HTTP/MCP deployment from an external network against public DNS and trusted TLS.

## OAuth proof

The external probe must verify discovery, token introspection, exact audience, required scope, expiry rejection, wrong-audience rejection, replay protection and rate limiting.

## mTLS proof

A separate direct endpoint must reject missing or untrusted client certificates, accept valid and rotated certificates, reject revoked certificates and prove TLS passthrough to PSMatrix.

## State

`PACK_REQUIRED` — local protocol tests pass, but a reproducible public deployment workflow and external authority proof still need to be integrated.
