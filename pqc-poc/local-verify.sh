#!/usr/bin/env bash
# =============================================================================
# Local, OFFLINE proof (no Docker required) that this machine's crypto stack
# genuinely performs post-quantum operations. Verifies:
#   1. ML-KEM-768 (Kyber) encapsulate/decapsulate round-trip via OpenSSL 3.5+
#   2. The SSH client offers ML-KEM / SNTRUP hybrid key exchange
#   3. ML-DSA (Dilithium) signature algorithms are available
#
# This is the primitive-level proof. The full end-to-end SSH handshake against
# a live server is covered by ./verify.sh (which needs Docker).
# =============================================================================
set -euo pipefail

pass=0; fail=0
ok(){ echo "   PASS: $1"; pass=$((pass+1)); }
no(){ echo "   FAIL: $1"; fail=$((fail+1)); }

echo "== Toolchain =="
command -v openssl >/dev/null || { echo "openssl not found"; exit 2; }
openssl version
echo

echo "== 1. ML-KEM-768 (Kyber) encapsulate/decapsulate round-trip =="
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
openssl genpkey -algorithm ML-KEM-768 -out "$TMP/priv.pem"
openssl pkey -in "$TMP/priv.pem" -pubout -out "$TMP/pub.pem"
# Sender encapsulates against the public key -> ciphertext + sender's secret.
openssl pkeyutl -encap -inkey "$TMP/pub.pem" -pubin -secret "$TMP/ss_send.bin" -out "$TMP/ct.bin"
# Recipient decapsulates the ciphertext -> recipient's secret.
openssl pkeyutl -decap -inkey "$TMP/priv.pem" -in "$TMP/ct.bin" -secret "$TMP/ss_recv.bin"
if cmp -s "$TMP/ss_send.bin" "$TMP/ss_recv.bin"; then
    ok "shared secrets match (ciphertext=$(wc -c <"$TMP/ct.bin")B, secret=$(wc -c <"$TMP/ss_send.bin")B)"
else
    no "shared secrets differ -- ML-KEM round-trip broken"
fi
echo

echo "== 2. SSH client post-quantum key-exchange support =="
if ssh -Q kex 2>/dev/null | grep -E 'mlkem|sntrup' ; then
    ok "SSH offers post-quantum hybrid key exchange"
else
    no "no PQC kex in this SSH build (need OpenSSH >= 8.5 for sntrup, >= 9.9 for mlkem)"
fi
echo

echo "== 3. ML-DSA (Dilithium) signature support =="
if openssl list -signature-algorithms 2>/dev/null | grep -qi 'ml-dsa'; then
    ok "ML-DSA (Dilithium) signatures available"
else
    no "no ML-DSA in this OpenSSL build (need OpenSSL >= 3.5)"
fi
echo

echo "== Summary: $pass passed, $fail failed =="
[ "$fail" -eq 0 ]
