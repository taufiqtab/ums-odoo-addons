from odoo import api, fields, models


class ResConfigSettings(models.TransientModel):
    _inherit = "res.config.settings"

    ums_base_url = fields.Char(
        string="UMS Base URL",
        config_parameter="ums_auth.base_url",
        help="Base URL of the UMS server (e.g. https://ums.yourserver.com)",
    )
    ums_app_id = fields.Char(
        string="UMS App ID",
        config_parameter="ums_auth.app_id",
        help="Application ID registered in UMS",
    )
    ums_callback_url = fields.Char(
        string="UMS Callback URL",
        config_parameter="ums_auth.callback_url",
        help="Callback URL for this Odoo instance (e.g. https://odoo.yourserver.com/ums/callback)",
    )
    ums_default_groups = fields.Char(
        string="Default Groups (XML IDs)",
        config_parameter="ums_auth.default_groups",
        default="base.group_user",
        help="Comma-separated XML IDs of groups for auto-created users (e.g. base.group_user,stock.group_stock_user)",
    )
