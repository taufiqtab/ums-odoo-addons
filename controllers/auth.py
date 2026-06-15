"""UMS SSO login and callback controller."""

import logging

from odoo import http
from odoo.http import request

_logger = logging.getLogger(__name__)


class UmsAuthController(http.Controller):

    @http.route("/ums/login", type="http", auth="none")
    def ums_login(self, redirect="/web", **kwargs):
        """Redirect to UMS login page."""
        base_url = request.env["ir.config_parameter"].sudo().get_param("ums_auth.base_url")
        app_id = request.env["ir.config_parameter"].sudo().get_param("ums_auth.app_id")
        callback_url = request.env["ir.config_parameter"].sudo().get_param("ums_auth.callback_url")

        if not base_url or not app_id:
            return request.redirect("/web/login?error=ums_not_configured")

        url = f"{base_url}/auth/login?app_id={app_id}&redirect_uri={callback_url}"
        return request.redirect(url)

    @http.route("/ums/callback", type="http", auth="none")
    def ums_callback(self, token=None, refresh_token=None, error=None, **kwargs):
        """Handle UMS callback after login. Auto-creates user if not exists."""
        if error or not token:
            _logger.warning("UMS callback error: %s", error)
            return request.redirect(f"/web/login?error={error or 'no_token'}")

        try:
            from ..lib.ums_client import validate_token
            claims = validate_token(token)
        except Exception as e:
            _logger.warning("UMS token validation failed: %s", e)
            return request.redirect("/web/login?error=invalid_token")

        email = claims.get("email")
        if not email:
            return request.redirect("/web/login?error=no_email_in_token")

        # Find or create Odoo user
        user = request.env["res.users"].sudo().search([("login", "=", email)], limit=1)
        if not user:
            user = self._create_user_from_claims(claims)
            _logger.info("UMS auto-created Odoo user: %s", email)

        # Store UMS data in session
        request.session["ums_user"] = claims
        request.session["ums_token"] = token
        request.session["ums_refresh_token"] = refresh_token

        # Authenticate Odoo session
        request.session.authenticate(request.db, email, {"type": "ums", "token": token})
        return request.redirect("/web")

    @http.route("/ums/logout", type="http", auth="user")
    def ums_logout(self, **kwargs):
        """Logout from Odoo and UMS."""
        base_url = request.env["ir.config_parameter"].sudo().get_param("ums_auth.base_url")
        callback_url = request.env["ir.config_parameter"].sudo().get_param("ums_auth.callback_url", "")
        login_url = callback_url.rsplit("/", 1)[0] + "/web/login" if callback_url else "/web/login"

        request.session.logout()

        if base_url:
            return request.redirect(f"{base_url}/auth/logout?redirect_uri={login_url}")
        return request.redirect("/web/login")

    def _create_user_from_claims(self, claims):
        """Create a new res.users from UMS JWT claims."""
        email = claims["email"]
        name = claims.get("name") or email.split("@")[0]

        # Get default company
        company = request.env["res.company"].sudo().search([], limit=1)

        # Get default groups from config, fallback to "Internal User"
        group_ids = self._get_default_groups()

        vals = {
            "login": email,
            "name": name,
            "email": email,
            "company_id": company.id,
            "company_ids": [(4, company.id)],
            "groups_id": [(6, 0, group_ids)],
            # No password — login only via UMS SSO
            "password": False,
        }

        return request.env["res.users"].sudo().create(vals)

    def _get_default_groups(self):
        """Get default group IDs for auto-created users."""
        ICP = request.env["ir.config_parameter"].sudo()
        group_xmlids = ICP.get_param("ums_auth.default_groups", "base.group_user")

        group_ids = []
        for xmlid in group_xmlids.split(","):
            xmlid = xmlid.strip()
            if xmlid:
                group = request.env.ref(xmlid, raise_if_not_found=False)
                if group:
                    group_ids.append(group.id)

        # Fallback: at least Internal User
        if not group_ids:
            group = request.env.ref("base.group_user", raise_if_not_found=False)
            if group:
                group_ids.append(group.id)

        return group_ids
