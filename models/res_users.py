"""Override res.users for UMS SSO authentication — Odoo 17 compatible.

Follows the same pattern as Odoo's built-in auth_oauth module:
- Store UMS access token on user record
- Override _check_credentials to accept token as password
- Override _get_session_token_fields to include ums_access_token
"""

import logging

from odoo import fields, models
from odoo.exceptions import AccessDenied

_logger = logging.getLogger(__name__)


class ResUsersUms(models.Model):
    _inherit = "res.users"

    ums_access_token = fields.Char(
        string="UMS Access Token",
        copy=False,
        readonly=True,
        prefetch=False,
    )

    def _check_credentials(self, password, env):
        """Allow login with UMS token as credential.

        Follows the same pattern as auth_oauth:
        1. Try normal password check first
        2. If that fails, check if password matches ums_access_token
        """
        try:
            return super()._check_credentials(password, env)
        except AccessDenied:
            # Check if the password is actually a UMS token
            # Use sudo() to bypass access rights, same as auth_oauth
            passwd_allowed = env.get('interactive', True)
            if passwd_allowed and self.env.user.active:
                res = self.sudo().search([
                    ('id', '=', self.env.uid),
                    ('ums_access_token', '=', password),
                ])
                if res:
                    return
            raise

    def _get_session_token_fields(self):
        """Include ums_access_token in session token computation.

        This ensures that when the token changes, existing sessions
        are invalidated (same pattern as auth_oauth).
        """
        return super()._get_session_token_fields() | {"ums_access_token"}

    @property
    def SELF_READABLE_FIELDS(self):
        """Allow users to read their own UMS token field."""
        return super().SELF_READABLE_FIELDS + ["ums_access_token"]
