#!/usr/bin/env bash
# Generate disposable clear-signed Debian InRelease fixtures for the RNP probe.
# Never use these test keys for a real repository.
set -euo pipefail
umask 077

OUT="${1:-$PWD/rnp-fixtures}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$OUT"

new_home() {
  mkdir -m 700 "$1"
  gpg --batch --homedir "$1" --pinentry-mode loopback --passphrase '' \
    --quick-generate-key "$2" ed25519 sign 0 >/dev/null 2>&1
}

new_home "$WORK/trusted" "Cydia Successor Fixture Trusted <trusted@example.invalid>"
new_home "$WORK/other" "Cydia Successor Fixture Other <other@example.invalid>"
new_home "$WORK/expired" "Cydia Successor Fixture Expired <expired@example.invalid>"
new_home "$WORK/revoked" "Cydia Successor Fixture Revoked <revoked@example.invalid>"

fingerprint_for() {
  gpg --batch --homedir "$1" --with-colons --fingerprint |
    awk -F: '{if ($1 == "fpr") {print $10; exit}}'
}
TRUSTED_FPR="$(fingerprint_for "$WORK/trusted")"
OTHER_FPR="$(fingerprint_for "$WORK/other")"
test -n "$TRUSTED_FPR"
test -n "$OTHER_FPR"

# Import the second disposable secret key only into this temporary signing home
# so GnuPG can create a genuine two-signature clear-signed message.
gpg --batch --homedir "$WORK/other" --export-secret-keys "$OTHER_FPR" > "$WORK/other-secret.gpg"
gpg --batch --homedir "$WORK/trusted" --import "$WORK/other-secret.gpg" >/dev/null 2>&1

cat > "$WORK/Release" <<'EOF'
Origin: Cydia Successor Test
Label: Disposable Fixture Repository
Suite: stable
Codename: fixture
Date: Wed, 11 Nov 2026 00:00:00 UTC
Architectures: iphoneos-arm64
Components: main
SHA256:
EOF

gpg --batch --homedir "$WORK/trusted" --local-user "$TRUSTED_FPR" --armor --clearsign \
  --digest-algo SHA256 --output "$OUT/valid-trusted.InRelease" "$WORK/Release"
gpg --batch --homedir "$WORK/other" --armor --clearsign \
  --digest-algo SHA256 --output "$OUT/valid-other.InRelease" "$WORK/Release"

# Create signatures first, then expire/revoke their public keys. The signatures
# were valid when made; the verifier must reject the now-expired/revoked keys.
EXPIRED_FPR="$(fingerprint_for "$WORK/expired")"
gpg --batch --homedir "$WORK/expired" --local-user "$EXPIRED_FPR" --armor --clearsign \
  --digest-algo SHA256 --output "$OUT/expired-key.InRelease" "$WORK/Release"
gpg --batch --homedir "$WORK/expired" --quick-set-expire "$EXPIRED_FPR" seconds=1
sleep 2

REVOKED_FPR="$(fingerprint_for "$WORK/revoked")"
gpg --batch --homedir "$WORK/revoked" --local-user "$REVOKED_FPR" --armor --clearsign \
  --digest-algo SHA256 --output "$OUT/revoked-key.InRelease" "$WORK/Release"
printf 'y\n0\n\n y\n' | script -q -e -c \
  "gpg --homedir '$WORK/revoked' --output '$WORK/revocation.asc' --gen-revoke '$REVOKED_FPR'" /dev/null >/dev/null
gpg --batch --homedir "$WORK/revoked" --import "$WORK/revocation.asc" >/dev/null 2>&1

# A SHA-1 signature is cryptographically generated but must be rejected by policy.
gpg --batch --homedir "$WORK/trusted" --local-user "$TRUSTED_FPR" --armor --clearsign \
  --digest-algo SHA1 --output "$OUT/weak-hash.InRelease" "$WORK/Release"

# A real message with two valid signatures. V1 intentionally blocks ambiguity.
gpg --batch --homedir "$WORK/trusted" --local-user "$TRUSTED_FPR" \
  --local-user "$OTHER_FPR" --armor --clearsign --digest-algo SHA256 \
  --output "$OUT/multiple-signatures.InRelease" "$WORK/Release"

# Modify only the cleartext payload, preserving the original signature block.
python3 - "$OUT/valid-trusted.InRelease" "$OUT/tampered-payload.InRelease" <<'PY'
import pathlib, sys
src = pathlib.Path(sys.argv[1]).read_bytes()
marker = b"-----BEGIN PGP SIGNATURE-----"
head, sep, tail = src.partition(marker)
if not sep or b"Origin: Cydia Successor Test" not in head:
    raise SystemExit("Unexpected clearsigned fixture framing")
pathlib.Path(sys.argv[2]).write_bytes(
    head.replace(b"Origin: Cydia Successor Test", b"Origin: Tampered Repository", 1)
    + sep + tail
)
PY

# Change one base64 character in the signature payload, not its armor delimiters.
python3 - "$OUT/valid-trusted.InRelease" "$OUT/tampered-signature.InRelease" <<'PY'
import pathlib, sys
src = pathlib.Path(sys.argv[1]).read_bytes()
marker = b"-----BEGIN PGP SIGNATURE-----"
head, sep, tail = src.partition(marker)
if not sep:
    raise SystemExit("Missing signature block")
lines = tail.splitlines(keepends=True)
for i, line in enumerate(lines):
    stripped = line.strip()
    if stripped and not stripped.startswith(b"=") and all(c in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=" for c in stripped):
        pos = next((j for j, c in enumerate(line) if c in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"), None)
        if pos is None:
            continue
        line = line[:pos] + (b"A" if line[pos:pos+1] != b"A" else b"B") + line[pos+1:]
        lines[i] = line
        break
else:
    raise SystemExit("No signature payload line found")
pathlib.Path(sys.argv[2]).write_bytes(head + sep + b"".join(lines))
PY

# Malformed framing and truncation are independent parser-rejection cases.
head -c 96 "$OUT/valid-trusted.InRelease" > "$OUT/truncated.InRelease"
python3 - "$OUT/valid-trusted.InRelease" "$OUT/malformed-framing.InRelease" <<'PY'
import pathlib, sys
src = pathlib.Path(sys.argv[1]).read_bytes()
marker = b"-----BEGIN PGP SIGNED MESSAGE-----"
if not src.startswith(marker):
    raise SystemExit("Unexpected clear-signed message header")
pathlib.Path(sys.argv[2]).write_bytes(
    b"-----BEGIN PGP SIGNED MESSAGE----X" + src[len(marker):]
)
PY
cp "$WORK/Release" "$OUT/unsigned.Release"

# Export only public keys. The verifier must never receive test secret keys.
gpg --batch --homedir "$WORK/trusted" --export "$TRUSTED_FPR" > "$OUT/trusted-keyring.gpg"
gpg --batch --homedir "$WORK/other" --export "$OTHER_FPR" > "$OUT/other-keyring.gpg"
gpg --batch --homedir "$WORK/trusted" --export "$TRUSTED_FPR" "$OTHER_FPR" > "$OUT/combined-keyring.gpg"
gpg --batch --homedir "$WORK/expired" --export "$EXPIRED_FPR" > "$OUT/expired-keyring.gpg"
gpg --batch --homedir "$WORK/revoked" --export "$REVOKED_FPR" > "$OUT/revoked-keyring.gpg"
printf '%s\n' "$TRUSTED_FPR" > "$OUT/trusted-primary.fingerprint"
printf '%s\n' "$OTHER_FPR" > "$OUT/other-primary.fingerprint"
printf '%s\n' "$EXPIRED_FPR" > "$OUT/expired-primary.fingerprint"
printf '%s\n' "$REVOKED_FPR" > "$OUT/revoked-primary.fingerprint"
: > "$OUT/empty-keyring.gpg"

(
  cd "$OUT"
  sha256sum *.InRelease *.Release *.gpg > SHA256SUMS
)

echo "Generated disposable RNP fixtures in: $OUT"
echo "Cases: valid-trusted, valid-other, tampered-payload, tampered-signature, truncated, malformed-framing, unsigned, missing-key, weak-hash, multiple-signatures, expired-key, revoked-key"
