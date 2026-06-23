# 🔴 → ✅ Security gates — RESOLVED (design) 2026-06-23

The release/signing/distribution subsystems were gated on these. Decisions are now made
(Khaled, 2026-06-23). Signing/distribution code may proceed **per the design below**, with the
hard rule that the **production private key is generated and held OFFLINE** — never on this
server, never on a shared host, never in CI.

| # | Gate | Resolution |
|---|---|---|
| 1 | Update-trust bootstrap | **Bake the ed25519 PUBLIC key (with a key-id) into the installer/image.** Trust-on-first-install; no network needed, nothing to intercept. The product ships a small **trust store** of public keys: `{active, next}`. |
| 2 | Key rotation / compromise | **Key-id + dual-trust overlap.** Every manifest carries `key_id`. Boxes trust a small set. Rotate by: generate new keypair offline → publish a *trust-update* (a manifest signed by the CURRENT key that adds the new public key) → boxes adopt it → switch signing to the new key → retire the old after an overlap window. **Compromise:** publish a revocation (signed by a still-trusted key) removing the bad `key_id`; boxes reject manifests signed by a revoked/unknown key. If ALL keys are compromised → out-of-band emergency installer (rare, documented). |
| 3 | Key custody + DR/escrow | **Offline air-gapped signing.** Private signing + license keys are generated and kept on an **offline machine / encrypted media**; releases are signed offline and only the **signed manifest + artifacts** are uploaded. **`netplex-support` NEVER holds a private key** — it only serves already-signed content. Escrow: encrypted key backup on **2 offline media in separate locations**. DR: because the server holds no key, losing it is fully recoverable (restore Postgres + object store from backup, redeploy; keys stay safe offline). |
| 4 | Self-updating the update agent | **Container two-phase swap performed by compose, not the agent.** The agent runs as a container; "self-update" = pull the new agent image → **compose recreates the update-agent container** (the agent never overwrites the file it's executing) → health-gate → rollback to the previous agent image on failure. A tiny, rarely-changed bootstrap/supervisor owns the swap so the updater is never mid-flight on itself. |
| 5 | Box↔central contract versioning | **Versioned manifest + negotiated API.** Manifest carries `schema_version`; the box sends its `agent_version` + supported schema range; central returns a manifest at a compatible schema or signals *"update the agent first."* Policy: central keeps serving the **oldest still-supported schema** to old boxes — an old box never breaks. |

## Hard operational rules (carry into build)
- **Never generate or store the production private key on this server or any shared host.** Do it
  offline. The repo ships only **public** keys + a *signing tool meant to run offline*.
- Verification (public-key) is server/box side and fully buildable now.
- A **test/dev keypair** may exist in the repo for tests ONLY, clearly marked non-production, and
  must never be added to a box's real trust store.

## Still tracked (operational/policy, not blockers)
User notifications · data retention/deletion · client crash-flood guard · support observability ·
responsible-disclosure policy · known-issues surface · staged-rollout % · first-run consent.
