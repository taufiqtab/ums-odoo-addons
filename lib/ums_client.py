"""Core UMS client: JWKS fetch, token validation, permission helpers."""

import logging
import time

import jwt
import requests
from jwt.algorithms import RSAAlgorithm

_logger = logging.getLogger(__name__)

# JWKS cache
_jwks_cache = {"key": None, "fetched_at": 0}
_JWKS_TTL = 3600  # 1 hour


def _get_ums_base_url():
    """Get UMS base URL from Odoo system parameters."""
    from odoo.http import request
    return request.env["ir.config_parameter"].sudo().get_param("ums_auth.base_url", "")


def _get_public_key(base_url=None):
    """Fetch and cache the RSA public key from UMS JWKS endpoint."""
    now = time.time()
    if _jwks_cache["key"] and (now - _jwks_cache["fetched_at"]) < _JWKS_TTL:
        return _jwks_cache["key"]

    if not base_url:
        base_url = _get_ums_base_url()

    resp = requests.get(f"{base_url}/.well-known/jwks.json", timeout=10)
    resp.raise_for_status()
    jwks = resp.json()
    key = RSAAlgorithm.from_jwk(jwks["keys"][0])

    _jwks_cache["key"] = key
    _jwks_cache["fetched_at"] = now
    return key


def validate_token(token, base_url=None):
    """Validate a UMS JWT and return decoded claims dict."""
    public_key = _get_public_key(base_url)
    return jwt.decode(token, public_key, algorithms=["RS256"])


def get_user():
    """Get current UMS user claims from session. Returns dict or None."""
    from odoo.http import request
    return request.session.get("ums_user")


def has_permission(module, permission):
    """Check if current user has a specific permission in a module."""
    user = get_user()
    if not user:
        return False
    for mod in user.get("modules", []):
        if mod["module"] == module and permission in mod.get("permissions", []):
            return True
    return False


def has_role(module, role):
    """Check if current user has a specific role in a module."""
    user = get_user()
    if not user:
        return False
    for mod in user.get("modules", []):
        if mod["module"] == module and role in mod.get("roles", []):
            return True
    return False


def has_module(module):
    """Check if current user has access to a module."""
    user = get_user()
    if not user:
        return False
    return any(mod["module"] == module for mod in user.get("modules", []))


def refresh_token(refresh_tok, base_url=None):
    """Exchange refresh token for a new token pair."""
    if not base_url:
        base_url = _get_ums_base_url()
    resp = requests.post(
        f"{base_url}/auth/refresh",
        json={"refresh_token": refresh_tok},
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json()["data"]
