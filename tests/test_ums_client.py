"""Unit tests for UMS client library."""

import time
import json
from unittest.mock import patch, MagicMock

from odoo.tests.common import TransactionCase


class TestUmsClientJWKS(TransactionCase):
    """Test JWKS fetching and caching."""

    def setUp(self):
        super().setUp()
        # Reset JWKS cache before each test
        from ..lib import ums_client
        ums_client._jwks_cache["keys"] = None
        ums_client._jwks_cache["fetched_at"] = 0

    @patch("requests.get")
    def test_get_public_key_fetches_jwks(self, mock_get):
        """Test that _get_public_key fetches from JWKS endpoint."""
        from ..lib.ums_client import _get_public_key

        # Mock JWKS response with a valid RSA key
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "keys": [{
                "kty": "RSA",
                "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
                "e": "AQAB",
                "alg": "RS256",
                "use": "sig",
            }]
        }
        mock_get.return_value = mock_response

        key = _get_public_key(base_url="https://ums.test.com")

        mock_get.assert_called_once_with(
            "https://ums.test.com/.well-known/jwks.json", timeout=10
        )
        self.assertIsNotNone(key)

    @patch("requests.get")
    def test_get_public_key_uses_cache(self, mock_get):
        """Test that subsequent calls use cached key."""
        from ..lib import ums_client
        from ..lib.ums_client import _get_public_key

        # Pre-populate cache
        fake_key = MagicMock()
        ums_client._jwks_cache["keys"] = [fake_key]
        ums_client._jwks_cache["fetched_at"] = time.time()

        key = _get_public_key(base_url="https://ums.test.com")

        # Should not have made a network call
        mock_get.assert_not_called()
        self.assertEqual(key, fake_key)

    @patch("requests.get")
    def test_get_public_key_refreshes_expired_cache(self, mock_get):
        """Test that expired cache triggers JWKS refetch."""
        from ..lib import ums_client
        from ..lib.ums_client import _get_public_key

        # Set cache as expired (2 hours ago)
        fake_key = MagicMock()
        ums_client._jwks_cache["keys"] = [fake_key]
        ums_client._jwks_cache["fetched_at"] = time.time() - 7200

        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "keys": [{
                "kty": "RSA",
                "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
                "e": "AQAB",
                "alg": "RS256",
                "use": "sig",
            }]
        }
        mock_get.return_value = mock_response

        key = _get_public_key(base_url="https://ums.test.com")

        mock_get.assert_called_once()
        self.assertIsNotNone(key)
        # Key should be different from fake_key (new key from JWKS)
        self.assertNotEqual(key, fake_key)

    def test_get_public_key_raises_without_base_url(self):
        """Test error when no base URL configured."""
        from ..lib.ums_client import _get_public_key

        with self.assertRaises(ValueError) as ctx:
            _get_public_key(base_url="")

        self.assertIn("not configured", str(ctx.exception))

    @patch("requests.get")
    def test_get_public_key_stale_fallback(self, mock_get):
        """Test stale cache fallback when JWKS endpoint is unreachable."""
        import requests as req_lib
        from ..lib import ums_client
        from ..lib.ums_client import _get_public_key

        # Pre-populate cache (expired)
        fake_key = MagicMock()
        ums_client._jwks_cache["keys"] = [fake_key]
        ums_client._jwks_cache["fetched_at"] = time.time() - 7200

        # Simulate network error
        mock_get.side_effect = req_lib.ConnectionError("Network unreachable")

        key = _get_public_key(base_url="https://ums.test.com")

        # Should fallback to stale cached key
        self.assertEqual(key, fake_key)

    def test_invalidate_jwks_cache(self):
        """Test cache invalidation."""
        from ..lib import ums_client
        from ..lib.ums_client import invalidate_jwks_cache

        ums_client._jwks_cache["keys"] = [MagicMock()]
        ums_client._jwks_cache["fetched_at"] = time.time()

        invalidate_jwks_cache()

        self.assertIsNone(ums_client._jwks_cache["keys"])
        self.assertEqual(ums_client._jwks_cache["fetched_at"], 0)


class TestUmsClientHelpers(TransactionCase):
    """Test permission/role helper functions."""

    def _mock_session_user(self, claims):
        """Helper to mock session with UMS user claims."""
        patcher = patch("odoo.http.request")
        self.mock_request = patcher.start()
        self.addCleanup(patcher.stop)
        self.mock_request.session = {"ums_user": claims}

    def test_has_permission_true(self):
        """Test has_permission returns True when user has permission."""
        from ..lib.ums_client import has_permission

        self._mock_session_user({
            "user_id": "123",
            "email": "test@test.com",
            "modules": [
                {"module": "inventory", "roles": ["admin"], "permissions": ["read", "write"]},
            ]
        })

        self.assertTrue(has_permission("inventory", "read"))
        self.assertTrue(has_permission("inventory", "write"))

    def test_has_permission_false(self):
        """Test has_permission returns False when user lacks permission."""
        from ..lib.ums_client import has_permission

        self._mock_session_user({
            "user_id": "123",
            "email": "test@test.com",
            "modules": [
                {"module": "inventory", "roles": ["viewer"], "permissions": ["read"]},
            ]
        })

        self.assertFalse(has_permission("inventory", "delete"))
        self.assertFalse(has_permission("other_module", "read"))

    def test_has_permission_no_user(self):
        """Test has_permission returns False when no user in session."""
        from ..lib.ums_client import has_permission

        patcher = patch("odoo.http.request")
        mock_request = patcher.start()
        self.addCleanup(patcher.stop)
        mock_request.session = {}

        self.assertFalse(has_permission("inventory", "read"))

    def test_has_role_true(self):
        """Test has_role returns True when user has role."""
        from ..lib.ums_client import has_role

        self._mock_session_user({
            "user_id": "123",
            "email": "test@test.com",
            "modules": [
                {"module": "inventory", "roles": ["admin", "viewer"], "permissions": ["read"]},
            ]
        })

        self.assertTrue(has_role("inventory", "admin"))

    def test_has_role_false(self):
        """Test has_role returns False when user lacks role."""
        from ..lib.ums_client import has_role

        self._mock_session_user({
            "user_id": "123",
            "email": "test@test.com",
            "modules": [
                {"module": "inventory", "roles": ["viewer"], "permissions": ["read"]},
            ]
        })

        self.assertFalse(has_role("inventory", "admin"))

    def test_has_module_true(self):
        """Test has_module returns True when user has module."""
        from ..lib.ums_client import has_module

        self._mock_session_user({
            "user_id": "123",
            "email": "test@test.com",
            "modules": [
                {"module": "inventory", "roles": [], "permissions": []},
                {"module": "dashboard", "roles": [], "permissions": []},
            ]
        })

        self.assertTrue(has_module("inventory"))
        self.assertTrue(has_module("dashboard"))

    def test_has_module_false(self):
        """Test has_module returns False when user lacks module."""
        from ..lib.ums_client import has_module

        self._mock_session_user({
            "user_id": "123",
            "email": "test@test.com",
            "modules": [
                {"module": "inventory", "roles": [], "permissions": []},
            ]
        })

        self.assertFalse(has_module("reports"))

    def test_get_modules(self):
        """Test get_modules returns all module claims."""
        from ..lib.ums_client import get_modules

        modules = [
            {"module": "inventory", "roles": ["admin"], "permissions": ["read"]},
            {"module": "dashboard", "roles": ["viewer"], "permissions": ["read"]},
        ]
        self._mock_session_user({
            "user_id": "123",
            "email": "test@test.com",
            "modules": modules,
        })

        result = get_modules()
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["module"], "inventory")
        self.assertEqual(result[1]["module"], "dashboard")

    def test_get_permissions(self):
        """Test get_permissions returns permissions for a module."""
        from ..lib.ums_client import get_permissions

        self._mock_session_user({
            "user_id": "123",
            "email": "test@test.com",
            "modules": [
                {"module": "inventory", "roles": [], "permissions": ["read", "write", "delete"]},
            ]
        })

        perms = get_permissions("inventory")
        self.assertEqual(perms, ["read", "write", "delete"])

    def test_get_permissions_unknown_module(self):
        """Test get_permissions returns empty list for unknown module."""
        from ..lib.ums_client import get_permissions

        self._mock_session_user({
            "user_id": "123",
            "email": "test@test.com",
            "modules": [],
        })

        perms = get_permissions("unknown")
        self.assertEqual(perms, [])

    def test_get_roles(self):
        """Test get_roles returns roles for a module."""
        from ..lib.ums_client import get_roles

        self._mock_session_user({
            "user_id": "123",
            "email": "test@test.com",
            "modules": [
                {"module": "inventory", "roles": ["admin", "editor"], "permissions": []},
            ]
        })

        roles = get_roles("inventory")
        self.assertEqual(roles, ["admin", "editor"])


class TestUmsClientRefresh(TransactionCase):
    """Test token refresh functionality."""

    @patch("requests.post")
    def test_refresh_token_success(self, mock_post):
        """Test successful token refresh."""
        from ..lib.ums_client import refresh_token

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "success": True,
            "data": {
                "token": "new_access_token",
                "refresh_token": "new_refresh_token",
            }
        }
        mock_post.return_value = mock_response

        result = refresh_token("old_refresh_token", base_url="https://ums.test.com")

        mock_post.assert_called_once_with(
            "https://ums.test.com/auth/refresh",
            json={"refresh_token": "old_refresh_token"},
            timeout=10,
        )
        self.assertEqual(result["token"], "new_access_token")
        self.assertEqual(result["refresh_token"], "new_refresh_token")

    @patch("requests.post")
    def test_refresh_token_failure(self, mock_post):
        """Test token refresh with server error."""
        import requests as req_lib
        from ..lib.ums_client import refresh_token

        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.raise_for_status.side_effect = req_lib.HTTPError("401")
        mock_post.return_value = mock_response

        with self.assertRaises(req_lib.HTTPError):
            refresh_token("bad_refresh_token", base_url="https://ums.test.com")

    def test_refresh_token_no_base_url(self):
        """Test refresh_token raises without base URL."""
        from ..lib.ums_client import refresh_token

        with self.assertRaises(ValueError):
            refresh_token("token", base_url="")

    @patch("requests.post")
    def test_validate_token_remote_success(self, mock_post):
        """Test remote token validation."""
        from ..lib.ums_client import validate_token_remote

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": {
                "user_id": "123",
                "email": "test@test.com",
                "modules": [],
            }
        }
        mock_post.return_value = mock_response

        claims = validate_token_remote("some_token", base_url="https://ums.test.com")

        self.assertEqual(claims["user_id"], "123")
        self.assertEqual(claims["email"], "test@test.com")

    @patch("requests.post")
    def test_validate_token_remote_failure(self, mock_post):
        """Test remote validation with invalid token."""
        from ..lib.ums_client import validate_token_remote

        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_post.return_value = mock_response

        with self.assertRaises(ValueError) as ctx:
            validate_token_remote("bad_token", base_url="https://ums.test.com")

        self.assertIn("401", str(ctx.exception))
