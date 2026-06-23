# 🔴 Security blockers — gates before any signing / distribution code

These MUST be resolved (designed + reviewed) before implementing the release/signing/distribution
subsystems (`app/routers/releases.py`, registry, offline bundles). Diagnostics + ticket +
license-*verify* paths are NOT blocked by these and may proceed.

| # | Blocker | Why it gates code | Resolution owner |
|---|---|---|---|
| 1 | **Update-trust bootstrap** | A fresh install must trust the *first* public key. If wrong, the whole signed-update chain is theatre. Plan: bake the public key into the installer/image; trust-on-first-install. | Khaled + security review |
| 2 | **Signing-key compromise & rotation** | If the private key leaks, we need a pre-built way to revoke + rotate + push new trust to every box *without* the compromised key. | security review |
| 3 | **Key custody + DR/escrow** | This repo's host is a single point of failure holding the signing + license keys. Offline escrow + DB DR required, or a dead host = can never ship a trusted update again. | Khaled |
| 4 | **Self-updating the update agent** | The updater updating itself must not brick the update mechanism (two-phase swap). | design |
| 5 | **Box↔central contract versioning** | Old boxes must keep talking to a newer central. Version the API + manifest. | design |

## Not blockers, but track (operational/policy)

- User notifications (in-app + email for paid; SPF/DKIM for `support@`).
- Data retention + deletion (PII now stored for identified tiers).
- Client-side crash-flood guard (lives in the product, but intake here needs rate-limit too).
- Support-system observability (ticket volume, MTTR, update success vs rollback rate).
- Responsible-disclosure / security-advisory policy.
- "Known issues / already reported" public surface.
- Staged-rollout %, release approval checklist, changelog quality, first-run consent.

See full context: `netplex/docs/platform/living-system.md` §8 + the completeness pass.
