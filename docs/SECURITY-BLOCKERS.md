# 🔴 → ✅ Security gates - RESOLVED (design) 2026-06-23

The release/signing/distribution subsystems were gated on these. Decisions are now made
(Khaled, 2026-06-23). Signing/distribution code may proceed **per the design below**, with the
hard rule that the **production private key is generated and held OFFLINE** - never on this
server, never on a shared host, never in CI.

| # | Gate | Resolution |
|---|---|---|
| 1 | Update-trust bootstrap | **Bake the ed25519 PUBLIC key (with a key-id) into the installer/image.** Trust-on-first-install; no network needed, nothing to intercept. The product ships a small **trust store** of public keys: `{active, next}`. |
| 2 | Key rotation / compromise | **Key-id + dual-trust overlap.** Every manifest carries `key_id`. Boxes trust a small set. Rotate by: generate new keypair offline → publish a *trust-update* (a manifest signed by the CURRENT key that adds the new public key) → boxes adopt it → switch signing to the new key → retire the old after an overlap window. **Compromise:** publish a revocation (signed by a still-trusted key) removing the bad `key_id`; boxes reject manifests signed by a revoked/unknown key. If ALL keys are compromised → out-of-band emergency installer (rare, documented). |
| 3 | Key custody + DR/escrow | **Offline air-gapped signing.** Private signing + license keys are generated and kept on an **offline machine / encrypted media**; releases are signed offline and only the **signed manifest + artifacts** are uploaded. **`netplex-support` NEVER holds a private key** - it only serves already-signed content. Escrow: encrypted key backup on **2 offline media in separate locations**. DR: because the server holds no key, losing it is fully recoverable (restore Postgres + object store from backup, redeploy; keys stay safe offline). |
| 4 | Self-updating the update agent | **Container two-phase swap performed by compose, not the agent.** The agent runs as a container; "self-update" = pull the new agent image → **compose recreates the update-agent container** (the agent never overwrites the file it's executing) → health-gate → rollback to the previous agent image on failure. A tiny, rarely-changed bootstrap/supervisor owns the swap so the updater is never mid-flight on itself. |
| 5 | Box↔central contract versioning | **Versioned manifest + negotiated API.** Manifest carries `schema_version`; the box sends its `agent_version` + supported schema range; central returns a manifest at a compatible schema or signals *"update the agent first."* Policy: central keeps serving the **oldest still-supported schema** to old boxes - an old box never breaks. |

## Hard operational rules (carry into build)
- **Never generate or store the production private key on this server or any shared host.** Do it
  offline. The repo ships only **public** keys + a *signing tool meant to run offline*.
- Verification (public-key) is server/box side and fully buildable now.
- A **test/dev keypair** may exist in the repo for tests ONLY, clearly marked non-production, and
  must never be added to a box's real trust store.

## ⏸ OUTSTANDING - deferred, NOT ready to build (recorded 2026-06-23)

These need the **production offline keypair to exist first** (Khaled generates it on an offline
machine via `tools/gen_keypair.py`), so they were deliberately not built at the time. **The real
production keypair now exists** (generated offline by Khaled, 2026-07-27; `key_id
f98ca2703f3ed827`, license half). Status as of 2026-07-27:

1. **Bake the public key + trust store into the product** - ship `{active, next}` public keys in
   the install image; the box's update agent verifies manifests against it (`app/crypto` verify
   lib is ready and tested). ⏸ Still outstanding - lives in the `netplex` product repo, not here.
2. **Manifest `schema_version` negotiation** - box advertises agent version + supported range;
   central serves the oldest compatible schema. ⏸ Still outstanding.
3. **Release/distribution endpoints** - ✅ **built 2026-07-27.** `POST /api/v1/releases/upload`
   (admin-only) accepts an ALREADY-SIGNED manifest (signed OFFLINE via `tools/sign_release.py` -
   this server never signs), verifies it against `SIGNING_PUBLIC_KEY`/`SIGNING_TRUST_STORE_JSON`,
   and stores it; `GET /api/v1/releases/manifest/{channel}` serves the latest stored+verified
   manifest. `POST /publish` (server-side signing) stays **permanently** 501 - that is the
   architectural boundary, not a temporary gate this closes. Registry publish / offline-bundle
   emitter are still not built (out of scope of the upload/verify/serve pipeline).
   `SIGNING_PUBLIC_KEY` is **not yet set** on the live host (only the license key is, so far) -
   until Khaled hands over the release-signing `.pub`, every upload correctly fails closed as
   `unknown-key`.
4. **Update agent + `netplexctl`** in the product - compose two-phase self-update, rollback.
   ⏸ Still outstanding.
5. **License issuance** - `/license/issue` stays **permanently** 501 (server-side minting needs
   the private license key, which this server must never hold). ✅ **Built 2026-07-27:** `POST
   /api/v1/license/register` (admin-only) accepts a token minted OFFLINE via
   `tools/mint_license.py`, verifies it against `LICENSE_PUBLIC_KEY`/`LICENSE_TRUST_STORE_JSON`,
   and stores it; `GET /api/v1/license/registered/{customer_ref}` looks it back up. This is the
   register-a-pre-signed-token path, not an issuance path - the custody rule is unchanged.

The crypto **primitives** (sign/verify, key-id, dual-trust, revocation) and the **offline tools**
(`tools/gen_keypair.py`, `tools/sign_release.py`, `tools/mint_license.py`) ARE built + tested. As
of 2026-07-27 the **receiving-end pipeline** for both (upload+verify+store+serve /
register+verify+store+lookup) is built + tested too (`tests/test_releases.py`,
`tests/test_license_register.py`). What's still missing: (a) the **separate release-signing
keypair** (docs/KEY-GENERATION-RUNBOOK.md §1) does not exist yet - only the license keypair
(§2) was generated 2026-07-27; Khaled needs to run `tools/gen_keypair.py netplex-signing-2026`
offline and set `SIGNING_PUBLIC_KEY` here before any manifest can ever be uploaded, and (b)
regardless of key, Khaled still has to actually run `tools/sign_release.py` /
`tools/mint_license.py` offline and upload/register the real signed output himself for either
pipeline to hold real production content - that step cannot be simulated or bypassed from here.
Plus items 1/2/4 above (product-repo/update-agent work, out of this repo's scope).

## Still tracked (operational/policy, not blockers)
User notifications · data retention/deletion · client crash-flood guard · support observability ·
responsible-disclosure policy · known-issues surface · staged-rollout % · first-run consent.
