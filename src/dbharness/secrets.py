"""Secret resolution — keep DSNs and keys out of config files and process args.

Any secret-bearing setting (a database DSN, an API key) may be given either as a
literal value or as a **reference** that names where to fetch it from:

* ``env:PGDSN``            — an environment variable
* ``file:/run/secrets/dsn``— a file's contents (trimmed)
* ``plain:literal``        — an explicit literal (escape hatch)
* ``postgresql://…``       — a bare literal (no known scheme) is used as-is

Deployments that use HashiCorp Vault, AWS Secrets Manager, GCP Secret Manager,
etc. register a provider for their scheme once at startup:

    from dbharness.secrets import register_provider
    register_provider("vault", lambda path: my_vault_client.read(path))

and then reference secrets as ``vault:secret/data/dbharness#dsn``. The rest of the
platform only ever calls :func:`resolve_secret`.
"""

from __future__ import annotations

import os
from typing import Callable, Dict

_Provider = Callable[[str], str]
_PROVIDERS: Dict[str, _Provider] = {}


class SecretError(RuntimeError):
    """Raised when a secret reference cannot be resolved."""


def register_provider(scheme: str, provider: _Provider) -> None:
    """Register a resolver for ``<scheme>:<locator>`` references."""
    _PROVIDERS[scheme.lower()] = provider


def resolve_secret(ref: str) -> str:
    """Resolve a secret reference to its value.

    A value whose scheme (text before the first ``:``) is a registered provider,
    and which is not a ``scheme://…`` URI, is fetched via that provider.
    Everything else — including full URIs like a Postgres DSN — is returned
    verbatim, so plain literals keep working.
    """
    if ref is None:
        raise SecretError("secret reference is None")
    scheme, sep, rest = ref.partition(":")
    if sep and not rest.startswith("//") and scheme.lower() in _PROVIDERS:
        return _PROVIDERS[scheme.lower()](rest)
    return ref


# -- built-in providers ------------------------------------------------------


def _env_provider(name: str) -> str:
    value = os.environ.get(name)
    if value is None:
        raise SecretError(f"environment variable {name!r} is not set")
    return value


def _file_provider(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read().strip()
    except OSError as exc:
        raise SecretError(f"could not read secret file {path!r}: {exc}") from exc


register_provider("env", _env_provider)
register_provider("file", _file_provider)
register_provider("plain", lambda literal: literal)
