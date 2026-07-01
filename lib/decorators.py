"""Decorators for Odoo controllers: @auth, @require, @require_role.

Compatible with Odoo 17 controller routing.
"""

import functools
import json
import logging

from odoo.http import Response, request

_logger = logging.getLogger(__name__)


def _json_error(message, status=401):
    """Return a JSON error response.
    
    For type='json' routes, we raise an exception or return a dict.
    For type='http' routes, we return a Response object.
    """
    from odoo.http import request
    # Check if this is a JSON-RPC request
    if request.httprequest.content_type and 'json' in request.httprequest.content_type:
        # For JSON-RPC routes, return error dict
        # Odoo wraps this in jsonrpc response automatically
        from odoo.exceptions import AccessDenied, AccessError
        if status == 403:
            raise AccessError(message)
        raise AccessDenied(message)
    return Response(
        json.dumps({"success": False, "message": message}),
        status=status,
        content_type="application/json",
    )


def auth(func):
    """Decorator: require valid UMS token in Authorization header or session.

    Usage:
        @http.route('/api/data', type='json', auth='none')
        @auth
        def get_data(self, **kwargs):
            ...
    """

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        from .ums_client import get_user, validate_token

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
    """Decorator: require specific UMS permission.

    Usage:
        @http.route('/api/items', type='json', auth='none')
        @require('inventory', 'read')
        def get_items(self, **kwargs):
            ...
    """

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
    """Decorator: require specific UMS role.

    Usage:
        @http.route('/api/admin', type='json', auth='none')
        @require_role('inventory', 'admin')
        def admin_action(self, **kwargs):
            ...
    """

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


def require_module(module):
    """Decorator: require access to specific UMS module.

    Usage:
        @http.route('/api/dashboard', type='json', auth='none')
        @require_module('dashboard')
        def dashboard(self, **kwargs):
            ...
    """

    def decorator(func):
        @functools.wraps(func)
        @auth
        def wrapper(*args, **kwargs):
            from .ums_client import has_module

            if not has_module(module):
                return _json_error(f"Module access denied: {module}", 403)
            return func(*args, **kwargs)

        return wrapper

    return decorator
