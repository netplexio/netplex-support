# netplex-support — architecture (receiving end)

```
                 outbound-only TLS 1.3 (boxes initiate; we never dial in)
   netplex box ───────────────────────────────────────────────▶  netplex-support
   (transmitting)                                                 (this repo, our cloud)
        │  opt-in ticket forward                                       │
        │  update/manifest/image pull                                  │
        │  license/tier verify                                         │
        └──────────────────────────────────────────────┐             │
                                                        ▼             ▼
   ┌──────────────────────────── netplex-support ────────────────────────────┐
   │                                                                          │
   │  API (FastAPI)                                                           │
   │   ├─ diagnostics  ── receive forwarded reports → ticket + blob          │
   │   ├─ tickets      ── triage console, status, claim, GitHub mirror       │
   │   ├─ licensing    ── verify (open) + issue (🔴 key-gated) license tokens │
   │   └─ releases 🔴  ── build manifest → ed25519 SIGN → publish (GATED)     │
   │                                                                          │
   │  Stores (source of truth)                                               │
   │   ├─ Postgres     ── tickets, licenses, install registry                │
   │   └─ Object store ── content-addressed screenshot/diagnostic blobs      │
   │                       (NEVER git)                                        │
   │                                                                          │
   │  Out-of-band                                                            │
   │   ├─ GitHub Issues  ── work mirror only (text + linked blobs)           │
   │   └─ Container registry ── signed images (🔴 gated)                      │
   └──────────────────────────────────────────────────────────────────────────┘
```

## Subsystems

### 1. Diagnostics destination
Receives a forwarded report (already redacted on the box). Verifies the sender's license token
(for tier), rate-limits, creates/updates a ticket (fingerprint dedupe), stores any screenshot as a
content-addressed blob in the object store. Anonymous (free) reports carry only a claim code.

### 2. Ticket / triage
Authoritative ticket DB. Triage console computes `priority_score` (severity × occurrences ×
tier_weight) and `sla_due`. "Open as GitHub issue" mirrors a ticket (text + blob links) to
`ikhal3d/netplex`; the issue number is stored back on the ticket. Release tags flip tickets to
`released` + stamp `fixed_in_version` (closes the loop the product dashboards read).

### 3. Licensing authority
- **Verify (open to build now):** validate a presented signed license token → return tier, expiry,
  entitlements. Stateless, key-public.
- **Issue (🔴 gated):** mint signed license tokens. Holds the private license key — gated on
  key-custody blocker.

### 4. Release / update authority — 🔴 GATED
Builds the release manifest, **ed25519-signs** it, pins per-service image digests, runs the
private registry, emits offline `.tar` bundles. Holds the private signing key. **Do not implement
until [SECURITY-BLOCKERS.md](SECURITY-BLOCKERS.md) #1–#5 are cleared.**

## Trust model
TLS protects transport; **ed25519 signatures protect payloads** (manifests, licenses). A box trusts
a public key baked into its install (trust-bootstrap). Even an offline box validates signatures, so
trust never depends on the transport.
