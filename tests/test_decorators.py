"""Unit tests for UMS controller decorators."""

import json
from unittest.mock import patch, MagicMock

from odoo.tests.common import TransactionCase


class TestDecorators(TransactionCase):
    """Test @auth, @require, @require_role, @require_module decorators."""

    def _make_mock_request(self, auth_header=None, session_user=None):
        """Create a mock request with optional auth header and session."""
        patcher = patch("odoo.http.request")
        self.mock_request = patcher.start()
        self.addCleanup(patcher.stop)

        # Mock httprequest headers
        headers = {}
        if auth_header:
            headers["Authorization"] = auth_header
        self.mock_request.httprequest.headers = headers

        # Mock session
        self.mock_request.session = {}
        if session_user:
            self.mock_request.session["ums_user"] = session_user

        return self.mock_request

    @patch("odoo.addons.ums_auth.lib.ums_client.validate_token")
    def test_auth_decorator_valid_bearer(self, mock_validate):
        """Test @auth passes with valid Bearer token."""
        from ..lib.decorators import auth

        mock_validate.return_value = {
            "user_id": "123",
            "email": "test@test.com",
            "modules": [],
        }

        self._make_mock_request(auth_header="Bearer valid_token")

        @auth
        def my_handler():
            return {"status": "ok"}

        result = my_handler()
        self.assertEqual(result, {"status": "ok"})
        mock_validate.assert_called_once_with("valid_token")

    def test_auth_decorator_session_user(self):
        """Test @auth passes when user already in session."""
        from ..lib.decorators import auth

        self._make_mock_request(session_user={
            "user_id": "123",
            "email": "test@test.com",
            "modules": [],
        })

        @auth
        def my_handler():
            return {"status": "ok"}

        result = my_handler()
        self.assertEqual(result, {"status": "ok"})

    def test_auth_decorator_no_token(self):
        """Test @auth returns 401 when no token provided."""
        from ..lib.decorators import auth

        self._make_mock_request()

        @auth
        def my_handler():
            return {"status": "ok"}

        result = my_handler()
        # Should be a Response with 401
        self.assertEqual(result.status_code, 401)
        body = json.loads(result.get_data(as_text=True))
        self.assertFalse(body["success"])
        self.assertIn("Missing", body["message"])

    @patch("odoo.addons.ums_auth.lib.ums_client.validate_token")
    def test_auth_decorator_invalid_token(self, mock_validate):
        """Test @auth returns 401 when token is invalid."""
        from ..lib.decorators import auth

        mock_validate.side_effect = Exception("Token expired")
        self._make_mock_request(auth_header="Bearer invalid_token")

        @auth
        def my_handler():
            return {"status": "ok"}

        result = my_handler()
        self.assertEqual(result.status_code, 401)
        body = json.loads(result.get_data(as_text=True))
        self.assertIn("Invalid", body["message"])

    def test_require_decorator_has_permission(self):
        """Test @require passes when user has permission."""
        from ..lib.decorators import require

        self._make_mock_request(session_user={
            "user_id": "123",
            "email": "test@test.com",
            "modules": [
                {"module": "inventory", "roles": [], "permissions": ["read", "write"]},
            ],
        })

        @require("inventory", "read")
        def my_handler():
            return {"status": "ok"}

        result = my_handler()
        self.assertEqual(result, {"status": "ok"})

    def test_require_decorator_lacks_permission(self):
        """Test @require returns 403 when user lacks permission."""
        from ..lib.decorators import require

        self._make_mock_request(session_user={
            "user_id": "123",
            "email": "test@test.com",
            "modules": [
                {"module": "inventory", "roles": [], "permissions": ["read"]},
            ],
        })

        @require("inventory", "delete")
        def my_handler():
            return {"status": "ok"}

        result = my_handler()
        self.assertEqual(result.status_code, 403)
        body = json.loads(result.get_data(as_text=True))
        self.assertIn("Permission denied", body["message"])

    def test_require_role_decorator_has_role(self):
        """Test @require_role passes when user has role."""
        from ..lib.decorators import require_role

        self._make_mock_request(session_user={
            "user_id": "123",
            "email": "test@test.com",
            "modules": [
                {"module": "inventory", "roles": ["admin"], "permissions": []},
            ],
        })

        @require_role("inventory", "admin")
        def my_handler():
            return {"status": "ok"}

        result = my_handler()
        self.assertEqual(result, {"status": "ok"})

    def test_require_role_decorator_lacks_role(self):
        """Test @require_role returns 403 when user lacks role."""
        from ..lib.decorators import require_role

        self._make_mock_request(session_user={
            "user_id": "123",
            "email": "test@test.com",
            "modules": [
                {"module": "inventory", "roles": ["viewer"], "permissions": []},
            ],
        })

        @require_role("inventory", "admin")
        def my_handler():
            return {"status": "ok"}

        result = my_handler()
        self.assertEqual(result.status_code, 403)
        body = json.loads(result.get_data(as_text=True))
        self.assertIn("Role denied", body["message"])

    def test_require_module_decorator_has_module(self):
        """Test @require_module passes when user has module access."""
        from ..lib.decorators import require_module

        self._make_mock_request(session_user={
            "user_id": "123",
            "email": "test@test.com",
            "modules": [
                {"module": "dashboard", "roles": [], "permissions": []},
            ],
        })

        @require_module("dashboard")
        def my_handler():
            return {"status": "ok"}

        result = my_handler()
        self.assertEqual(result, {"status": "ok"})

    def test_require_module_decorator_lacks_module(self):
        """Test @require_module returns 403 when user lacks module."""
        from ..lib.decorators import require_module

        self._make_mock_request(session_user={
            "user_id": "123",
            "email": "test@test.com",
            "modules": [
                {"module": "inventory", "roles": [], "permissions": []},
            ],
        })

        @require_module("admin_panel")
        def my_handler():
            return {"status": "ok"}

        result = my_handler()
        self.assertEqual(result.status_code, 403)
        body = json.loads(result.get_data(as_text=True))
        self.assertIn("Module access denied", body["message"])
