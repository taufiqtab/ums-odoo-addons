"""
Example controller demonstrating UMS Auth decorators.

Copy this file as reference when integrating UMS authentication
into your own Odoo module.

Import pattern for YOUR module (not inside ums_auth itself):

    from odoo.addons.ums_auth import (
        auth, require, require_role, require_module,
        get_user, has_permission, has_role, has_module,
        get_modules, get_permissions, get_roles,
    )

Test endpoints:
    POST /ums/example/profile       - requires valid UMS token (@auth)
    POST /ums/example/dashboard     - requires module 'dashboard' (@require_module)
    POST /ums/example/view          - requires 'dashboard.view' permission (@require)
    POST /ums/example/delete        - requires 'dashboard.delete' permission (@require)
    POST /ums/example/admin         - requires 'dashboard.admin' role (@require_role)
    POST /ums/example/inventory     - requires module 'inventory' (@require_module) — will 403
    POST /ums/example/superadmin    - requires 'dashboard.superadmin' role — will 403

Usage with curl:
    TOKEN="your_jwt_token_here"

    # Should return 200 with user profile
    curl -s http://localhost:8069/ums/example/profile \\
        -H "Content-Type: application/json" \\
        -H "Authorization: Bearer $TOKEN" \\
        -d '{"jsonrpc":"2.0","method":"call","params":{}}'

    # Should return 403 (no inventory module)
    curl -s http://localhost:8069/ums/example/inventory \\
        -H "Content-Type: application/json" \\
        -H "Authorization: Bearer $TOKEN" \\
        -d '{"jsonrpc":"2.0","method":"call","params":{}}'
"""

from odoo import http
from odoo.addons.ums_auth.lib.decorators import (
    auth,
    require,
    require_role,
    require_module,
)
from odoo.addons.ums_auth.lib.ums_client import (
    get_user,
    get_modules,
    get_permissions,
    get_roles,
    has_permission,
    has_role,
    has_module,
)


class UmsExampleController(http.Controller):
    """Example controller showing UMS Auth integration patterns."""

    # -------------------------------------------------------------------------
    # 1. Basic auth — just requires valid UMS token
    # -------------------------------------------------------------------------
    @http.route("/ums/example/profile", type="json", auth="none", methods=["POST"])
    @auth
    def example_profile(self, **kwargs):
        """Get current user profile from UMS token.

        Decorator: @auth
        - Validates Bearer token from Authorization header
        - Or uses existing UMS session
        - Stores claims in request.session['ums_user']
        """
        user = get_user()
        return {
            "success": True,
            "message": "Authenticated successfully",
            "data": {
                "user_id": user.get("user_id"),
                "email": user.get("email"),
                "app_id": user.get("app_id"),
                "modules": get_modules(),
            },
        }

    # -------------------------------------------------------------------------
    # 2. Module access check — requires access to specific module
    # -------------------------------------------------------------------------
    @http.route("/ums/example/dashboard", type="json", auth="none", methods=["POST"])
    @require_module("dashboard")
    def example_dashboard(self, **kwargs):
        """Access dashboard module.

        Decorator: @require_module('dashboard')
        - First validates token (inherits @auth)
        - Then checks user has 'dashboard' in their modules
        - Returns 403 if module not assigned
        """
        return {
            "success": True,
            "message": "You have access to dashboard module",
            "data": {
                "roles": get_roles("dashboard"),
                "permissions": get_permissions("dashboard"),
            },
        }

    @http.route("/ums/example/inventory", type="json", auth="none", methods=["POST"])
    @require_module("inventory")
    def example_inventory(self, **kwargs):
        """Access inventory module — will return 403 if user doesn't have it.

        Decorator: @require_module('inventory')
        """
        return {
            "success": True,
            "message": "You have access to inventory module",
        }

    # -------------------------------------------------------------------------
    # 3. Permission check — requires specific permission in a module
    # -------------------------------------------------------------------------
    @http.route("/ums/example/view", type="json", auth="none", methods=["POST"])
    @require("dashboard", "view")
    def example_view(self, **kwargs):
        """View dashboard data.

        Decorator: @require('dashboard', 'view')
        - Checks user has 'view' permission in 'dashboard' module
        """
        return {
            "success": True,
            "message": "You have 'view' permission on dashboard",
        }

    @http.route("/ums/example/delete", type="json", auth="none", methods=["POST"])
    @require("dashboard", "delete")
    def example_delete(self, **kwargs):
        """Delete dashboard item.

        Decorator: @require('dashboard', 'delete')
        - Checks user has 'delete' permission in 'dashboard' module
        """
        return {
            "success": True,
            "message": "You have 'delete' permission on dashboard",
        }

    @http.route("/ums/example/export", type="json", auth="none", methods=["POST"])
    @require("dashboard", "export")
    def example_export(self, **kwargs):
        """Export dashboard data — will 403 if user lacks 'export' permission.

        Decorator: @require('dashboard', 'export')
        """
        return {
            "success": True,
            "message": "You have 'export' permission on dashboard",
        }

    # -------------------------------------------------------------------------
    # 4. Role check — requires specific role in a module
    # -------------------------------------------------------------------------
    @http.route("/ums/example/admin", type="json", auth="none", methods=["POST"])
    @require_role("dashboard", "admin")
    def example_admin(self, **kwargs):
        """Admin-only action.

        Decorator: @require_role('dashboard', 'admin')
        - Checks user has 'admin' role in 'dashboard' module
        """
        return {
            "success": True,
            "message": "You have 'admin' role on dashboard",
        }

    @http.route("/ums/example/superadmin", type="json", auth="none", methods=["POST"])
    @require_role("dashboard", "superadmin")
    def example_superadmin(self, **kwargs):
        """Superadmin-only action — will 403 since user only has 'admin' role.

        Decorator: @require_role('dashboard', 'superadmin')
        """
        return {
            "success": True,
            "message": "You have 'superadmin' role on dashboard",
        }

    # -------------------------------------------------------------------------
    # 5. Manual permission check — using helper functions directly
    # -------------------------------------------------------------------------
    @http.route("/ums/example/check", type="json", auth="none", methods=["POST"])
    @auth
    def example_manual_check(self, **kwargs):
        """Demonstrate manual permission checking with helper functions.

        Sometimes you need conditional logic based on permissions
        rather than a hard 403. Use helper functions directly.
        """
        user = get_user()
        return {
            "success": True,
            "message": "Manual permission check results",
            "data": {
                "email": user.get("email"),
                "checks": {
                    "has_module_dashboard": has_module("dashboard"),
                    "has_module_inventory": has_module("inventory"),
                    "can_view_dashboard": has_permission("dashboard", "view"),
                    "can_delete_dashboard": has_permission("dashboard", "delete"),
                    "can_export_dashboard": has_permission("dashboard", "export"),
                    "is_dashboard_admin": has_role("dashboard", "admin"),
                    "is_dashboard_viewer": has_role("dashboard", "viewer"),
                },
            },
        }
