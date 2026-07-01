"""Unit tests for UMS auth controller."""

from unittest.mock import patch, MagicMock

from odoo.tests.common import HttpCase, TransactionCase


class TestUmsAuthControllerUnit(TransactionCase):
    """Unit tests for controller helper methods."""

    def test_get_default_groups_basic(self):
        """Test _get_default_groups returns correct group IDs."""
        from ..controllers.auth import UmsAuthController

        # Set config parameter
        self.env["ir.config_parameter"].sudo().set_param(
            "ums_auth.default_groups", "base.group_user"
        )

        controller = UmsAuthController()
        # We need to patch request.env to use self.env
        with patch("odoo.http.request") as mock_request:
            mock_request.env = self.env
            group_ids = controller._get_default_groups()

        group_user = self.env.ref("base.group_user")
        self.assertIn(group_user.id, group_ids)

    def test_get_default_groups_multiple(self):
        """Test _get_default_groups with multiple groups."""
        from ..controllers.auth import UmsAuthController

        self.env["ir.config_parameter"].sudo().set_param(
            "ums_auth.default_groups", "base.group_user, base.group_system"
        )

        controller = UmsAuthController()
        with patch("odoo.http.request") as mock_request:
            mock_request.env = self.env
            group_ids = controller._get_default_groups()

        self.assertEqual(len(group_ids), 2)

    def test_get_default_groups_invalid_xmlid(self):
        """Test _get_default_groups handles invalid XML IDs gracefully."""
        from ..controllers.auth import UmsAuthController

        self.env["ir.config_parameter"].sudo().set_param(
            "ums_auth.default_groups", "base.group_user, nonexistent.group_foo"
        )

        controller = UmsAuthController()
        with patch("odoo.http.request") as mock_request:
            mock_request.env = self.env
            group_ids = controller._get_default_groups()

        # Should only have the valid group
        group_user = self.env.ref("base.group_user")
        self.assertIn(group_user.id, group_ids)
        self.assertEqual(len(group_ids), 1)

    def test_get_default_groups_fallback(self):
        """Test _get_default_groups fallback to base.group_user."""
        from ..controllers.auth import UmsAuthController

        # Set empty/invalid config
        self.env["ir.config_parameter"].sudo().set_param(
            "ums_auth.default_groups", ""
        )

        controller = UmsAuthController()
        with patch("odoo.http.request") as mock_request:
            mock_request.env = self.env
            group_ids = controller._get_default_groups()

        # Should fallback to base.group_user
        group_user = self.env.ref("base.group_user")
        self.assertIn(group_user.id, group_ids)


class TestUmsAuthControllerCreateUser(TransactionCase):
    """Test user creation from UMS claims."""

    def test_create_user_from_claims(self):
        """Test _create_user_from_claims creates user correctly."""
        from ..controllers.auth import UmsAuthController

        claims = {
            "user_id": "uuid-123",
            "email": "newuser@example.com",
            "name": "New User",
            "modules": [],
        }

        self.env["ir.config_parameter"].sudo().set_param(
            "ums_auth.default_groups", "base.group_user"
        )

        controller = UmsAuthController()
        with patch("odoo.http.request") as mock_request:
            mock_request.env = self.env
            user = controller._create_user_from_claims(claims)

        self.assertEqual(user.login, "newuser@example.com")
        self.assertEqual(user.name, "New User")
        self.assertEqual(user.email, "newuser@example.com")
        # User should not have a password
        self.assertFalse(user.password)

    def test_create_user_name_fallback(self):
        """Test user creation with name fallback from email."""
        from ..controllers.auth import UmsAuthController

        claims = {
            "user_id": "uuid-456",
            "email": "john.doe@example.com",
            # No 'name' field
            "modules": [],
        }

        self.env["ir.config_parameter"].sudo().set_param(
            "ums_auth.default_groups", "base.group_user"
        )

        controller = UmsAuthController()
        with patch("odoo.http.request") as mock_request:
            mock_request.env = self.env
            user = controller._create_user_from_claims(claims)

        # Should use email prefix as name
        self.assertEqual(user.name, "john.doe")


class TestUmsConfigSettings(TransactionCase):
    """Test UMS configuration settings."""

    def test_config_parameters_exist(self):
        """Test that config parameters can be set and read."""
        ICP = self.env["ir.config_parameter"].sudo()

        ICP.set_param("ums_auth.base_url", "https://ums.test.com")
        ICP.set_param("ums_auth.app_id", "test-app")
        ICP.set_param("ums_auth.callback_url", "https://odoo.test.com/ums/callback")
        ICP.set_param("ums_auth.default_groups", "base.group_user")

        self.assertEqual(ICP.get_param("ums_auth.base_url"), "https://ums.test.com")
        self.assertEqual(ICP.get_param("ums_auth.app_id"), "test-app")
        self.assertEqual(ICP.get_param("ums_auth.callback_url"), "https://odoo.test.com/ums/callback")
        self.assertEqual(ICP.get_param("ums_auth.default_groups"), "base.group_user")

    def test_res_config_settings_fields(self):
        """Test that settings fields exist in res.config.settings."""
        fields = self.env["res.config.settings"]._fields
        self.assertIn("ums_base_url", fields)
        self.assertIn("ums_app_id", fields)
        self.assertIn("ums_callback_url", fields)
        self.assertIn("ums_default_groups", fields)
