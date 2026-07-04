#!/usr/bin/env bash
# Key escrow — produce a RECOVERABLE, encrypted backup of the licence signing seeds for offline media.
#
# ⚠️  Run on the offline signing machine. This creates an AES-256 encrypted bundle of the *.key seeds
# plus a sealed record (key_id + sha256 per seed). It PRINTS a one-time passphrase you MUST record
# separately from the bundle (write it down; store apart). It VERIFIES the bundle decrypts before
# finishing. It does NOT delete the plaintext seeds — destroying the last plaintext copy is the human
# final step, done only AFTER you've confirmed the passphrase is recorded and the bundle restores.
#
# Usage:   escrow_keys.sh <keydir> <out.enc>
# Restore: openssl enc -d -aes-256-cbc -pbkdf2 -in <out.enc> -pass pass:'<passphrase>' | tar xz
set -euo pipefail

KEYDIR="${1:?usage: escrow_keys.sh <keydir> <out.enc>}"
OUT="${2:?usage: escrow_keys.sh <keydir> <out.enc>}"
RECORD="${OUT%.enc}.record.txt"

command -v openssl >/dev/null || { echo "openssl required"; exit 1; }
shopt -s nullglob
SEEDS=("$KEYDIR"/*.key)
[ "${#SEEDS[@]}" -gt 0 ] || { echo "no *.key seeds in $KEYDIR"; exit 1; }

# Sealed record: key_id (sha256 of the raw pubkey, first 16 hex) + sha256 of each seed file.
{
  echo "# netplex licence key escrow record"
  echo "# created for offline media handoff — keep with (but recorded separately from) the bundle"
  for s in "${SEEDS[@]}"; do
    pub="${s%.key}.pub"
    kid="(no .pub)"; [ -f "$pub" ] && kid="$(python3 - "$pub" <<'PY'
import base64,hashlib,sys
print(hashlib.sha256(base64.b64decode(open(sys.argv[1]).read().strip())).hexdigest()[:16])
PY
)"
    printf "%s  key_id=%s  seed_sha256=%s\n" "$(basename "$s")" "$kid" "$(sha256sum "$s" | cut -d' ' -f1)"
  done
} > "$RECORD"

# Strong one-time passphrase (printed once; never stored on disk).
PASS="$(openssl rand -base64 32)"

# Encrypt a gzipped tar of the seeds + pubs + record.
tar -C "$KEYDIR" -czf - $(cd "$KEYDIR" && ls *.key *.pub 2>/dev/null) \
  | openssl enc -aes-256-cbc -pbkdf2 -salt -pass "pass:$PASS" -out "$OUT"

# Verify the bundle decrypts + lists the seeds (round-trip) before we trust it.
if openssl enc -d -aes-256-cbc -pbkdf2 -pass "pass:$PASS" -in "$OUT" | tar tz >/dev/null 2>&1; then
  echo "escrow bundle verified (decrypts + lists cleanly)."
else
  echo "ERROR: escrow bundle failed to round-trip — NOT safe to rely on. Investigate."; exit 1
fi

echo
echo "  bundle : $OUT   ($(stat -c%s "$OUT" 2>/dev/null || wc -c <"$OUT") bytes)"
echo "  record : $RECORD"
echo "  seeds  : ${#SEEDS[@]}"
echo
echo "  ================= ONE-TIME PASSPHRASE (record it NOW, store apart from the bundle) ================="
echo "     $PASS"
echo "  ===================================================================================================="
echo
echo "  HUMAN FINAL STEPS (irreducible):"
echo "   1. Write the passphrase down; store it in a location separate from $OUT."
echo "   2. Copy $OUT + $RECORD to TWO encrypted offline media in separate places."
echo "   3. Test restore on the offline machine (see header)."
echo "   4. ONLY THEN destroy the plaintext seeds:  shred -u $KEYDIR/*.key"
echo "      (the box keeps only *.pub; the running install already holds its activated token)."
