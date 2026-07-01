"""UMS SSO login and callback controller — Odoo 17 compatible."""

import logging

from werkzeug.utils import redirect as werkzeug_redirect

from odoo import http
from odoo.http import request
from odoo.exceptions import AccessDenied
from odoo.addons.web.controllers.utils import ensure_db

_logger = logging.getLogger(__name__)


class UmsAuthController(http.Controller):

    @http.route("/ums/login", type="http", auth="none")
    def ums_login(self, redirect="/web", **kwargs):
        """Redirect to UMS login page."""
        ensure_db()
        base_url = request.env["ir.config_parameter"].sudo().get_param("ums_auth.base_url")
        app_id = request.env["ir.config_parameter"].sudo().get_param("ums_auth.app_id")
        callback_url = request.env["ir.config_parameter"].sudo().get_param("ums_auth.callback_url")

        _logger.info("UMS login: base_url=%r, app_id=%r, callback=%r", base_url, app_id, callback_url)

        if not base_url or not app_id:
            _logger.warning("UMS not configured: base_url=%r, app_id=%r", base_url, app_id)
            return request.redirect("/web/login?error=ums_not_configured")

        url = f"{base_url}/auth/login?app_id={app_id}&redirect_uri={callback_url}"
        _logger.info("UMS redirecting to: %s", url)
        resp = werkzeug_redirect(url, code=303)
        resp.autocorrect_location_header = False
        return resp

    @http.route("/ums/callback", type="http", auth="none")
    def ums_callback(self, token=None, refresh_token=None, error=None, **kwargs):
        """Handle UMS callback after login. Auto-creates user if not exists."""
        ensure_db()
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

        # Store UMS token on user record for session authenticate
        user.sudo().write({"ums_access_token": token})
        # Commit so the token is visible to authenticate()'s own transaction
        request.env.cr.commit()

        # Store UMS data in session
        request.session["ums_user"] = claims
        request.session["ums_token"] = token
        request.session["ums_refresh_token"] = refresh_token

        # Authenticate Odoo session using token as credential
        # Odoo 17: request.session.authenticate(db, login, token_as_key)
        # Our custom _check_credentials in res.users validates ums_access_token
        dbname = request.session.db
        try:
            pre_uid = request.session.authenticate(dbname, email, token)
        except AccessDenied:
            _logger.error("UMS: session.authenticate failed for %s", email)
            return request.redirect("/web/login?error=auth_failed")

        return request.redirect("/web")

    @http.route("/ums/logout", type="http", auth="none")
    def ums_logout(self, **kwargs):
        """Logout from Odoo and UMS."""
        ensure_db()
        base_url = request.env["ir.config_parameter"].sudo().get_param("ums_auth.base_url")
        callback_url = request.env["ir.config_parameter"].sudo().get_param("ums_auth.callback_url", "")

        # Build login URL from callback: http://localhost:8069/ums/callback -> http://localhost:8069/web/login
        if callback_url:
            from urllib.parse import urlparse
            parsed = urlparse(callback_url)
            login_url = f"{parsed.scheme}://{parsed.netloc}/web/login"
        else:
            login_url = "/web/login"

        # Clear UMS session data
        request.session.pop("ums_user", None)
        request.session.pop("ums_token", None)
        request.session.pop("ums_refresh_token", None)
        request.session.logout()

        if base_url:
            url = f"{base_url}/auth/logout?redirect_uri={login_url}"
            resp = werkzeug_redirect(url, code=303)
            resp.autocorrect_location_header = False
            return resp
        return request.redirect("/web/login")

    @http.route("/ums/refresh", type="json", auth="none", methods=["POST"])
    def ums_refresh(self, **kwargs):
        """Refresh UMS token and update session."""
        refresh_tok = request.session.get("ums_refresh_token")
        if not refresh_tok:
            return {"success": False, "message": "No refresh token in session"}

        try:
            from ..lib.ums_client import refresh_token, validate_token
            result = refresh_token(refresh_tok)
            new_token = result["token"]
            new_refresh = result.get("refresh_token", refresh_tok)

            # Validate new token and update session
            claims = validate_token(new_token)
            request.session["ums_user"] = claims
            request.session["ums_token"] = new_token
            request.session["ums_refresh_token"] = new_refresh

            # Update user record
            if request.session.uid:
                user = request.env["res.users"].sudo().browse(request.session.uid)
                user.write({"ums_access_token": new_token})

            return {"success": True, "data": {"token": new_token}}
        except Exception as e:
            _logger.warning("UMS token refresh failed: %s", e)
            return {"success": False, "message": str(e)}

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
            # Odoo 17: set empty string, not False/None
            "password": "",
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
