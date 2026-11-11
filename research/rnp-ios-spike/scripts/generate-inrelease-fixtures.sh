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

# Add a dedicated signing subkey under the trusted primary.
gpg --batch --homedir "$WORK/trusted" --pinentry-mode loopback --passphrase "" --quick-add-key "$TRUSTED_FPR" ed25519 sign 0
SUBKEY_FPR="$(gpg --batch --homedir "$WORK/trusted" --with-colons --list-keys "$TRUSTED_FPR" |
  awk -F: '$1 == "sub" { want=1; next } want && $1 == "fpr" { print $10; exit }')"
test -n "$SUBKEY_FPR"

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

gpg --batch --homedir "$WORK/trusted" --local-user "$SUBKEY_FPR" --armor --clearsign \
  --digest-algo SHA256 --output "$OUT/valid-subkey.InRelease" "$WORK/Release"
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
# macOS's BSD script(1) does not support the GNU -c interface. Use
# Expect to answer GnuPG's interactive revocation prompts portably.
command -v expect >/dev/null 2>&1 || {
  echo "expect is required to generate the disposable revoked-key fixture" >&2
  exit 1
}
expect "$WORK/revoked" "$WORK/revocation.asc" "$REVOKED_FPR" <<'EXPECT' >/dev/null
set timeout 30
set home [lindex $argv 0]
set output [lindex $argv 1]
set fingerprint [lindex $argv 2]
spawn gpg --homedir $home --output $output --gen-revoke $fingerprint
expect {
  -re {Create a revocation certificate.*\(y/N\)} { send "y\r" }
  timeout { exit 10 }
  eof { exit 11 }
}
expect {
  -re {Your decision\?} { send "0\r" }
  timeout { exit 12 }
  eof { exit 13 }
}
expect {
  -re {Enter an optional description} { send "\r" }
  timeout { exit 14 }
  eof { exit 15 }
}
expect {
  -re {Is this okay\? \(y/N\)} { send "y\r" }
  timeout { exit 16 }
  eof { exit 17 }
}
expect eof
EXPECT
test -s "$WORK/revocation.asc"
gpg --batch --homedir "$WORK/revoked" --import "$WORK/revocation.asc" >/dev/null 2>&1

# A SHA-1 signature is cryptographically generated but must be rejected by policy.
gpg --batch --homedir "$WORK/trusted" --local-user "$TRUSTED_FPR" --armor --clearsign \
  --digest-algo SHA1 --output "$OUT/weak-hash.InRelease" "$WORK/Release"

# A future-dated signature must be rejected even when its key is trusted.
gpg --batch --homedir "$WORK/trusted" --faked-system-time 20300101T000000! \
  --local-user "$TRUSTED_FPR" --armor --clearsign \
  --digest-algo SHA256 --output "$OUT/future-signature.InRelease" "$WORK/Release"

# Create an old but cryptographically genuine signing key, then sign with a
# one-day signature lifetime in 2020. The signature is expired at test time,
# while the signing key itself remains valid.
mkdir -m 700 "$WORK/old-signer"
gpg --batch --homedir "$WORK/old-signer" --faked-system-time 20190101T000000! \
  --pinentry-mode loopback --passphrase '' \
  --quick-generate-key "Cydia Successor Fixture Old Signer <old@example.invalid>" ed25519 sign 0 >/dev/null 2>&1
OLD_FPR="$(fingerprint_for "$WORK/old-signer")"
gpg --batch --homedir "$WORK/old-signer" --faked-system-time 20200102T000000! \
  --default-sig-expire 1d --local-user "$OLD_FPR" --armor --clearsign \
  --digest-algo SHA256 --output "$OUT/expired-signature.InRelease" "$WORK/Release"

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
printf '%s\n' "$SUBKEY_FPR" > "$OUT/trusted-signing-subkey.fingerprint"
printf 'not an OpenPGP key bundle\n' > "$OUT/malformed-keyring.gpg"
head -c 16 "$OUT/trusted-keyring.gpg" > "$OUT/truncated-keyring.gpg"

# Deterministic malformed OpenPGP packet fixtures. These mutate only the
# exported public key bundle; no secret key material is written to fixtures.
python3 - "$OUT/trusted-keyring.gpg" "$OUT" <<'PY'
import pathlib, sys

source = pathlib.Path(sys.argv[1]).read_bytes()
out = pathlib.Path(sys.argv[2])
if len(source) < 8 or not (source[0] & 0x80):
    raise SystemExit("Unexpected OpenPGP public-key packet framing")

first = source[0]
if first & 0x40:
    tag = first & 0x3f
    if len(source) < 2:
        raise SystemExit("Truncated new-format packet header")
    length_octet = source[1]
    if length_octet < 192:
        body = 2
    elif length_octet <= 223:
        body = 3
    elif length_octet == 255:
        body = 6
    else:
        raise SystemExit("Unexpected partial-body packet in fixture keyring")
    new_format = True
else:
    tag = (first >> 2) & 0x0f
    length_type = first & 0x03
    body = (2, 3, 5, 1)[length_type]
    new_format = False

if tag != 6 or body + 6 > len(source):
    raise SystemExit("Expected a complete primary public-key packet first")

# Invalid CTB: bit 7 is clear.
(out / "bad-packet-header.gpg").write_bytes(bytes([0]) + source[1:])
# A packet header with no following length/body.
(out / "truncated-packet-header.gpg").write_bytes(source[:1])
# Declare an impossibly large first packet length without adding its body.
if new_format:
    oversized_header = bytes([0xC6, 0xFF, 0x7F, 0xFF, 0xFF, 0xFF])
else:
    oversized_header = bytes([0x9A, 0x7F, 0xFF])
(out / "invalid-packet-length.gpg").write_bytes(oversized_header + source[body:])
# The public-key packet algorithm octet follows version + 4-byte creation time.
mutated = bytearray(source)
mutated[body + 5] = 255
(out / "unsupported-key-algorithm.gpg").write_bytes(mutated)
PY
gpg --batch --homedir "$WORK/other" --export "$OTHER_FPR" > "$OUT/other-keyring.gpg"
gpg --batch --homedir "$WORK/trusted" --export "$TRUSTED_FPR" "$OTHER_FPR" > "$OUT/combined-keyring.gpg"
gpg --batch --homedir "$WORK/expired" --export "$EXPIRED_FPR" > "$OUT/expired-keyring.gpg"
gpg --batch --homedir "$WORK/revoked" --export "$REVOKED_FPR" > "$OUT/revoked-keyring.gpg"
gpg --batch --homedir "$WORK/old-signer" --export "$OLD_FPR" > "$OUT/old-signer-keyring.gpg"
printf '%s\n' "$TRUSTED_FPR" > "$OUT/trusted-primary.fingerprint"
printf '%s\n' "$OTHER_FPR" > "$OUT/other-primary.fingerprint"
printf '%s\n' "$EXPIRED_FPR" > "$OUT/expired-primary.fingerprint"
printf '%s\n' "$REVOKED_FPR" > "$OUT/revoked-primary.fingerprint"
printf '%s\n' "$OLD_FPR" > "$OUT/old-signer-primary.fingerprint"
: > "$OUT/empty-keyring.gpg"

(
  cd "$OUT"
  shasum -a 256 *.InRelease *.Release *.gpg > SHA256SUMS
)

echo "Generated disposable RNP fixtures in: $OUT"
echo "Cases: valid-trusted, valid-signing-subkey, valid-other, tampered-payload, tampered-signature, truncated, malformed-framing, unsigned, missing-key, malformed-keyring, weak-hash, multiple-signatures, expired-key, revoked-key"
