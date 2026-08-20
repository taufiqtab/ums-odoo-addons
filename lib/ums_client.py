"""Core UMS client: JWKS fetch, token validation, permission helpers.

Compatible with Odoo 17 (Python 3.10+).
"""

import logging
import time
import threading

import jwt
import requests
from jwt.algorithms import RSAAlgorithm

_logger = logging.getLogger(__name__)

# JWKS cache (thread-safe)
_jwks_lock = threading.Lock()
_jwks_cache = {"keys": None, "fetched_at": 0}
_JWKS_TTL = 3600  # 1 hour

# Modules cache (thread-safe, keyed by JTI)
_modules_lock = threading.Lock()
_modules_cache = {}  # {jti: {"modules": [...], "fetched_at": float}}
_MODULES_TTL = 300  # 5 minutes


def _get_ums_base_url():
    """Get UMS base URL from Odoo system parameters."""
    from odoo.http import request
    return request.env["ir.config_parameter"].sudo().get_param("ums_auth.base_url", "")


def _get_public_key(base_url=None):
    """Fetch and cache the RSA public key from UMS JWKS endpoint.

    Thread-safe with lock to prevent multiple concurrent JWKS fetches.
    """
    now = time.time()
    with _jwks_lock:
        if _jwks_cache["keys"] and (now - _jwks_cache["fetched_at"]) < _JWKS_TTL:
            return _jwks_cache["keys"][0]

    if not base_url:
        base_url = _get_ums_base_url()

    if not base_url:
        raise ValueError("UMS base URL not configured")

    try:
        resp = requests.get(f"{base_url}/.well-known/jwks.json", timeout=10, verify=False)
        resp.raise_for_status()
        jwks = resp.json()
    except requests.RequestException as e:
        _logger.error("UMS: Failed to fetch JWKS from %s: %s", base_url, e)
        # Return cached key if available (stale is better than nothing)
        with _jwks_lock:
            if _jwks_cache["keys"]:
                _logger.warning("UMS: Using stale cached JWKS key")
                return _jwks_cache["keys"][0]
        raise

    if not jwks.get("keys"):
        raise ValueError("UMS JWKS response has no keys")

    # Parse all keys, store first one as primary
    keys = []
    for key_data in jwks["keys"]:
        keys.append(RSAAlgorithm.from_jwk(key_data))

    with _jwks_lock:
        _jwks_cache["keys"] = keys
        _jwks_cache["fetched_at"] = time.time()

    return keys[0]


def invalidate_jwks_cache():
    """Force JWKS cache invalidation (useful after key rotation)."""
    with _jwks_lock:
        _jwks_cache["keys"] = None
        _jwks_cache["fetched_at"] = 0


def validate_token(token, base_url=None):
    """Validate a UMS JWT and return decoded claims dict.

    Args:
        token: JWT string from UMS
        base_url: Optional UMS base URL override

    Returns:
        dict with decoded JWT claims

    Raises:
        jwt.ExpiredSignatureError: Token has expired
        jwt.InvalidTokenError: Token is invalid
        ValueError: JWKS not available
    """
    public_key = _get_public_key(base_url)
    try:
        return jwt.decode(token, public_key, algorithms=["RS256"])
    except jwt.ExpiredSignatureError:
        _logger.debug("UMS: Token expired, attempting JWKS refresh")
        # Try refreshing JWKS in case of key rotation
        invalidate_jwks_cache()
        public_key = _get_public_key(base_url)
        return jwt.decode(token, public_key, algorithms=["RS256"])


def fetch_modules(token, base_url=None):
    """Fetch user modules from UMS API.

    Used for lean JWT tokens that don't include modules in payload.

    Args:
        token: JWT access token string
        base_url: Optional UMS base URL override

    Returns:
        list of module claim dicts

    Raises:
        requests.RequestException: Network error
        ValueError: Invalid response
    """
    if not base_url:
        base_url = _get_ums_base_url()

    if not base_url:
        raise ValueError("UMS base URL not configured")

    resp = requests.get(
        f"{base_url}/api/v1/me/modules",
        headers={"Authorization": f"Bearer {token}"},
        timeout=10,
        verify=False,
    )
    resp.raise_for_status()
    data = resp.json()
    return data.get("data", [])


def validate_token_with_modules(token, base_url=None):
    """Validate token and auto-fetch modules if lean token (with caching).

    This is the recommended method for apps using lean tokens.
    Modules are cached in-memory for 5 minutes keyed by JTI,
    so subsequent requests with the same token won't hit the API.

    Args:
        token: JWT string from UMS
        base_url: Optional UMS base URL override

    Returns:
        dict with decoded JWT claims (modules always populated)

    Raises:
        jwt.ExpiredSignatureError: Token has expired
        jwt.InvalidTokenError: Token is invalid
        ValueError: JWKS or URL not available
    """
    claims = validate_token(token, base_url)

    # If modules are already in token (full JWT), return as-is
    if claims.get("modules"):
        return claims

    # Cache key: use JTI (unique per token)
    cache_key = claims.get("jti", f"{claims.get('user_id', '')}:{claims.get('app_id', '')}")

    # Try cache first
    now = time.time()
    with _modules_lock:
        entry = _modules_cache.get(cache_key)
        if entry and (now - entry["fetched_at"]) < _MODULES_TTL:
            claims["modules"] = entry["modules"]
            return claims

    # Cache miss — fetch from API
    modules = fetch_modules(token, base_url)

    # Store in cache
    with _modules_lock:
        _modules_cache[cache_key] = {"modules": modules, "fetched_at": now}

    claims["modules"] = modules
    return claims


def invalidate_modules_cache(jti=None):
    """Invalidate modules cache.

    Args:
        jti: Specific JTI to invalidate. If None, clears all cached modules.
    """
    with _modules_lock:
        if jti:
            _modules_cache.pop(jti, None)
        else:
            _modules_cache.clear()


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


def get_modules():
    """Get all module claims for current user. Returns list of dicts."""
    user = get_user()
    if not user:
        return []
    return user.get("modules", [])


def get_permissions(module):
    """Get all permissions for a specific module. Returns list of strings."""
    user = get_user()
    if not user:
        return []
    for mod in user.get("modules", []):
        if mod["module"] == module:
            return mod.get("permissions", [])
    return []


def get_roles(module):
    """Get all roles for a specific module. Returns list of strings."""
    user = get_user()
    if not user:
        return []
    for mod in user.get("modules", []):
        if mod["module"] == module:
            return mod.get("roles", [])
    return []


def refresh_token(refresh_tok, base_url=None):
    """Exchange refresh token for a new token pair.

    Args:
        refresh_tok: The refresh token string
        base_url: Optional UMS base URL override

    Returns:
        dict with 'token' and 'refresh_token' keys

    Raises:
        requests.RequestException: Network error
        ValueError: Invalid response
    """
    if not base_url:
        base_url = _get_ums_base_url()

    if not base_url:
        raise ValueError("UMS base URL not configured")

    resp = requests.post(
        f"{base_url}/auth/refresh",
        json={"refresh_token": refresh_tok},
        timeout=10,
        verify=False,
    )
    resp.raise_for_status()
    data = resp.json()

    if not data.get("success", True):
        raise ValueError(f"UMS refresh failed: {data.get('message', 'unknown error')}")

    return data["data"]


def validate_token_remote(token, base_url=None):
    """Validate token via UMS /auth/validate endpoint (server-side).

    Use this for extra security when local JWKS validation is not sufficient.

    Args:
        token: JWT string
        base_url: Optional UMS base URL override

    Returns:
        dict with validated claims

    Raises:
        requests.RequestException: Network error
        ValueError: Token invalid
    """
    if not base_url:
        base_url = _get_ums_base_url()

    if not base_url:
        raise ValueError("UMS base URL not configured")

    resp = requests.post(
        f"{base_url}/auth/validate",
        json={"token": token},
        timeout=10,
        verify=False,
    )

    if resp.status_code != 200:
        raise ValueError(f"UMS validate failed with status {resp.status_code}")

    data = resp.json()
    return data.get("data", data)
