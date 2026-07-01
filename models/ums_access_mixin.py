"""Mixin for Odoo models to check UMS permissions.

Compatible with Odoo 17. Inherit this mixin to add UMS permission
checks to any model.

Usage:
    class StockPicking(models.Model):
        _inherit = ['stock.picking', 'ums.access']

        def action_confirm(self):
            self.ums_require('inventory', 'write')
            return super().action_confirm()
"""

from odoo import models
from odoo.exceptions import AccessDenied


class UmsAccessMixin(models.AbstractModel):
    _name = "ums.access"
    _description = "UMS Access Mixin"

    def ums_can(self, module, permission):
        """Check if current user has permission. Returns bool."""
        from ..lib.ums_client import has_permission
        return has_permission(module, permission)

    def ums_has_role(self, module, role):
        """Check if current user has role. Returns bool."""
        from ..lib.ums_client import has_role
        return has_role(module, role)

    def ums_has_module(self, module):
        """Check if current user has access to a module. Returns bool."""
        from ..lib.ums_client import has_module
        return has_module(module)

    def ums_require(self, module, permission):
        """Require permission or raise AccessDenied."""
        if not self.ums_can(module, permission):
            raise AccessDenied(f"UMS permission denied: {module}.{permission}")

    def ums_require_role(self, module, role):
        """Require role or raise AccessDenied."""
        if not self.ums_has_role(module, role):
            raise AccessDenied(f"UMS role denied: {module}.{role}")

    def ums_require_module(self, module):
        """Require module access or raise AccessDenied."""
        if not self.ums_has_module(module):
            raise AccessDenied(f"UMS module access denied: {module}")
