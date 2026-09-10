#!/usr/bin/env python3

################################################################################
# Honeypot Framework - Shared Elasticsearch Connection Settings
#
# Every script in this directory talks to the same Elasticsearch cluster, which
# holds captured attacker traffic and audit evidence. Connection settings come
# from the environment (see .env.example): there is deliberately NO default
# password, and TLS certificate verification is on unless explicitly disabled.
################################################################################

import os

DEFAULT_ES_URL = "https://localhost:9200"
DEFAULT_CA_CERT = "/etc/honeypot-framework/ssl/ca-cert.pem"

_FALSEY = ("false", "0", "no", "off")


class ElasticsearchConfigError(RuntimeError):
    """Raised when required Elasticsearch settings are missing."""


def url() -> str:
    return os.getenv("ELASTICSEARCH_URL") or DEFAULT_ES_URL


def username() -> str:
    return os.getenv("ELASTICSEARCH_USERNAME", "elastic")


def password() -> str:
    value = os.getenv("ELASTICSEARCH_PASSWORD")
    if not value:
        raise ElasticsearchConfigError(
            "ELASTICSEARCH_PASSWORD is not set. Refusing to connect with a "
            "default password -- set it in .env (see .env.example)."
        )
    return value


def auth() -> tuple:
    return (username(), password())


def verify():
    """Value for `requests(verify=...)` / the ES client's cert settings.

    Returns the CA bundle path when one exists, True for the system trust
    store, or False only when verification is explicitly disabled.
    """
    if os.getenv("ELASTICSEARCH_VERIFY_CERTS", "true").lower() in _FALSEY:
        return False

    ca_cert = os.getenv("SSL_CA_CERT_PATH", DEFAULT_CA_CERT)
    return ca_cert if os.path.exists(ca_cert) else True


def build_client(host: str = None, **kwargs):
    """Create an `elasticsearch.Elasticsearch` client with the shared settings."""
    from elasticsearch import Elasticsearch

    verification = verify()
    params = {"basic_auth": auth(), "verify_certs": bool(verification)}
    if isinstance(verification, str):
        params["ca_certs"] = verification
    params.update(kwargs)

    return Elasticsearch([host or url()], **params)
