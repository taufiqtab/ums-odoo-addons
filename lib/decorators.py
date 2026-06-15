"""Decorators for Odoo controllers: @ums.auth, @ums.require, @ums.require_role."""

import functools
import json
import logging

from odoo.http import request, Response

_logger = logging.getLogger(__name__)


def _json_error(message, status=401):
    return Response(
        json.dumps({"success": False, "message": message}),
        status=status,
        content_type="application/json",
    )


def auth(func):
    """Decorator: require valid UMS token in Authorization header or session."""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        from .ums_client import validate_token, get_user

        # Already authenticated via session
        if get_user():
            return func(*args, **kwargs)

        # Try Bearer token from header
        auth_header = request.httprequest.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return _json_error("Missing authorization token")

        token = auth_header[7:]
        try:
            claims = validate_token(token)
            request.session["ums_user"] = claims
        except Exception as e:
            _logger.warning("UMS token validation failed: %s", e)
            return _json_error("Invalid or expired token")

        return func(*args, **kwargs)
    return wrapper


def require(module, permission):
    """Decorator: require specific UMS permission."""
    def decorator(func):
        @functools.wraps(func)
        @auth
        def wrapper(*args, **kwargs):
            from .ums_client import has_permission
            if not has_permission(module, permission):
                return _json_error(f"Permission denied: {module}.{permission}", 403)
            return func(*args, **kwargs)
        return wrapper
    return decorator


def require_role(module, role):
    """Decorator: require specific UMS role."""
    def decorator(func):
        @functools.wraps(func)
        @auth
        def wrapper(*args, **kwargs):
            from .ums_client import has_role
            if not has_role(module, role):
                return _json_error(f"Role denied: {module}.{role}", 403)
            return func(*args, **kwargs)
        return wrapper
    return decorator
