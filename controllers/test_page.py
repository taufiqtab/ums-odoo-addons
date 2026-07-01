"""
UMS Auth Test Page — accessible from Odoo menu.

Provides a visual dashboard to test UMS authentication,
permissions, roles, and module access.
"""

import json
import logging

from odoo import http
from odoo.http import request
from odoo.addons.ums_auth.lib.ums_client import (
    get_user,
    get_modules,
    get_permissions,
    get_roles,
    has_permission,
    has_role,
    has_module,
)

_logger = logging.getLogger(__name__)


class UmsTestPageController(http.Controller):

    @http.route("/ums/test", type="http", auth="user", website=False)
    def ums_test_page(self, **kwargs):
        """Render UMS Auth test dashboard page."""
        user = get_user()

        # If no UMS session, show message
        if not user:
            return request.render("ums_auth.test_page_no_session", {})

        # Build test results
        modules = get_modules()
        test_results = []

        # Module access tests
        module_names = [m["module"] for m in modules]
        test_modules = list(set(module_names + ["inventory", "reports", "admin_panel"]))
        for mod in sorted(test_modules):
            test_results.append({
                "type": "module",
                "label": f"@require_module('{mod}')",
                "description": f"Has access to module '{mod}'",
                "result": has_module(mod),
            })

        # Permission tests for each module user has
        for mod_claim in modules:
            mod_name = mod_claim["module"]
            perms = mod_claim.get("permissions", [])
            all_perms = list(set(perms + ["export", "admin_action"]))
            for perm in sorted(all_perms):
                test_results.append({
                    "type": "permission",
                    "label": f"@require('{mod_name}', '{perm}')",
                    "description": f"Has '{perm}' permission in '{mod_name}'",
                    "result": has_permission(mod_name, perm),
                })

        # Role tests for each module user has
        for mod_claim in modules:
            mod_name = mod_claim["module"]
            roles = mod_claim.get("roles", [])
            all_roles = list(set(roles + ["superadmin", "viewer", "editor"]))
            for role in sorted(all_roles):
                test_results.append({
                    "type": "role",
                    "label": f"@require_role('{mod_name}', '{role}')",
                    "description": f"Has '{role}' role in '{mod_name}'",
                    "result": has_role(mod_name, role),
                })

        values = {
            "user": user,
            "modules": modules,
            "test_results": test_results,
            "modules_json": json.dumps(modules, indent=2),
        }
        return request.render("ums_auth.test_page", values)
