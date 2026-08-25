# =============================================================================
# Multi-variant SSH honeypot -- classical + hybrid (stock OpenSSH)
# =============================================================================
# Alpine 3.21 ships OpenSSH 9.9, which supports the ML-KEM-768 hybrid key
# exchange `mlkem768x25519-sha256` (NIST-standardized "Kyber") and the older
# `sntrup761x25519-sha512@openssh.com`. No liboqs / OQS-OpenSSL build is needed
# for the classical or hybrid variants -- they differ only by KexAlgorithms.
# The pqc-only variant is a separate image (see Dockerfile.pqc-only).
# =============================================================================
FROM alpine:3.21

RUN apk add --no-cache openssh \
    && rm -f /etc/ssh/sshd_config \
    && mkdir -p /etc/ssh/keys /var/empty /var/log/pqc-honeypot \
    && chmod 711 /var/empty

COPY sshd_config.classical sshd_config.hybrid /etc/ssh/
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 0755 /usr/local/bin/entrypoint.sh

# classical=2222, hybrid=2223 (set in each config's Port directive)
ENV VARIANT=hybrid
EXPOSE 2222 2223

# Health = the variant's own port is accepting connections.
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD nc -z localhost "$(awk '/^Port /{print $2; exit}' /etc/ssh/sshd_config.$VARIANT)" || exit 1

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
