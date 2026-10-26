"""Load a :class:`Policy` from a YAML file.

Keeping policy as declarative, reviewable YAML (policy-as-code) means access
changes go through the same review/version-control flow as application code —
which is exactly what you want for an authorization surface.

API keys may be given either as a literal ``api_key`` (hashed on load, convenient
for demos) or as ``api_key_env`` naming an environment variable that holds the
key (preferred for real deployments so secrets stay out of the file).
"""

from __future__ import annotations

import hashlib
import os
from typing import Any, Dict

import yaml

from dbharness.policy.models import (
    Action,
    Effect,
    Permission,
    Policy,
    Principal,
    Role,
)


class PolicyError(ValueError):
    """Raised when a policy document is malformed."""


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def load_policy(path: str) -> Policy:
    with open(path, "r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh) or {}
    return parse_policy(raw)


def parse_policy(raw: Dict[str, Any]) -> Policy:
    roles = {name: _parse_role(name, body) for name, body in (raw.get("roles") or {}).items()}
    principals: Dict[str, Principal] = {}
    for entry in raw.get("principals") or []:
        principal = _parse_principal(entry)
        # Fail loudly if a principal references a role that does not exist —
        # a silent typo here is a silent authorization hole.
        for role_name in principal.roles:
            if role_name not in roles:
                raise PolicyError(
                    f"principal {principal.id!r} references unknown role {role_name!r}"
                )
        principals[principal.id] = principal
    return Policy(principals=principals, roles=roles)


def _parse_role(name: str, body: Dict[str, Any]) -> Role:
    perms = [_parse_permission(name, p) for p in (body.get("permissions") or [])]
    return Role(name=name, permissions=perms, description=body.get("description", ""))


def _parse_permission(role_name: str, body: Dict[str, Any]) -> Permission:
    try:
        actions = frozenset(Action(a.lower()) for a in body["actions"])
    except (KeyError, ValueError) as exc:
        raise PolicyError(f"role {role_name!r}: invalid or missing 'actions' ({exc})") from exc
    resources = frozenset(r.lower() for r in (body.get("resources") or ["*"]))
    deny_columns = frozenset(c.lower() for c in (body.get("deny_columns") or []))
    effect = Effect(body.get("effect", "allow").lower())
    return Permission(
        effect=effect,
        actions=actions,
        resources=resources,
        row_filter=body.get("row_filter"),
        deny_columns=deny_columns,
        require_approval=bool(body.get("require_approval", False)),
        description=body.get("description", ""),
    )


def _parse_principal(body: Dict[str, Any]) -> Principal:
    pid = body.get("id")
    if not pid:
        raise PolicyError("every principal needs an 'id'")

    if "api_key" in body:
        key_hash = sha256_hex(str(body["api_key"]))
    elif "api_key_sha256" in body:
        key_hash = str(body["api_key_sha256"]).lower()
    elif "api_key_env" in body:
        env_name = body["api_key_env"]
        raw_key = os.environ.get(env_name)
        if not raw_key:
            raise PolicyError(
                f"principal {pid!r}: env var {env_name!r} (api_key_env) is not set"
            )
        key_hash = sha256_hex(raw_key)
    else:
        raise PolicyError(
            f"principal {pid!r}: needs one of api_key / api_key_sha256 / api_key_env"
        )

    return Principal(
        id=pid,
        api_key_sha256=key_hash,
        roles=list(body.get("roles") or []),
        context={k: str(v) for k, v in (body.get("context") or {}).items()},
        owner=body.get("owner", ""),
        description=body.get("description", ""),
    )
