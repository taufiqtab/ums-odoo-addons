"""Unit tests for res.users UMS override."""

from odoo.tests.common import TransactionCase
from odoo.exceptions import AccessDenied


class TestResUsersUms(TransactionCase):
    """Test UMS authentication via res.users override."""

    def setUp(self):
        super().setUp()
        self.user = self.env["res.users"].create({
            "name": "UMS Test User",
            "login": "ums_test@example.com",
            "email": "ums_test@example.com",
            "password": "test_password_123",
        })

    def test_ums_access_token_field_exists(self):
        """Test that ums_access_token field is available on res.users."""
        self.assertIn("ums_access_token", self.env["res.users"]._fields)

    def test_ums_access_token_default_empty(self):
        """Test that ums_access_token is empty by default."""
        self.assertFalse(self.user.ums_access_token)

    def test_write_ums_access_token(self):
        """Test that ums_access_token can be written."""
        self.user.sudo().write({"ums_access_token": "test_jwt_token_123"})
        self.assertEqual(self.user.sudo().ums_access_token, "test_jwt_token_123")

    def test_check_credentials_normal_password(self):
        """Test that normal password authentication still works."""
        # Should not raise
        self.user._check_credentials("test_password_123", {"interactive": True})

    def test_check_credentials_wrong_password(self):
        """Test that wrong password raises AccessDenied."""
        with self.assertRaises(AccessDenied):
            self.user._check_credentials("wrong_password", {"interactive": True})

    def test_check_credentials_ums_token(self):
        """Test that UMS token is accepted as credential."""
        token = "eyJhbGciOiJSUzI1NiJ9.test_payload.test_signature"
        self.user.sudo().write({"ums_access_token": token})

        # Should not raise — token matches ums_access_token
        self.user._check_credentials(token, {"interactive": True})

    def test_check_credentials_wrong_token(self):
        """Test that wrong UMS token raises AccessDenied."""
        self.user.sudo().write({"ums_access_token": "correct_token"})

        with self.assertRaises(AccessDenied):
            self.user._check_credentials("wrong_token", {"interactive": True})

    def test_check_credentials_no_token_set(self):
        """Test that token auth fails when no token is stored."""
        # User has no ums_access_token set
        with self.assertRaises(AccessDenied):
            self.user._check_credentials("some_random_token", {"interactive": True})

    def test_session_token_fields_includes_ums(self):
        """Test that _get_session_token_fields includes ums_access_token."""
        fields = self.user._get_session_token_fields()
        self.assertIn("ums_access_token", fields)

    def test_session_token_fields_includes_standard(self):
        """Test that standard session token fields are still present."""
        fields = self.user._get_session_token_fields()
        # Standard Odoo fields should still be there
        self.assertIn("password", fields)

    def test_token_change_invalidates_session_token(self):
        """Test that changing ums_access_token changes session token."""
        self.user.sudo().write({"ums_access_token": "token_v1"})
        session_token_v1 = self.user._compute_session_token(self.env.cr.dbname)

        self.user.sudo().write({"ums_access_token": "token_v2"})
        session_token_v2 = self.user._compute_session_token(self.env.cr.dbname)

        # Session tokens should differ because ums_access_token changed
        self.assertNotEqual(session_token_v1, session_token_v2)
