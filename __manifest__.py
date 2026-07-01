{
    "name": "UMS Authentication",
    "version": "17.0.1.0.0",
    "category": "Technical",
    "summary": "SSO authentication & authorization via UMS (User Management System)",
    "author": "Kodepik",
    "website": "https://github.com/taufiqtab/ums-odoo-sdk",
    "license": "LGPL-3",
    "depends": ["base", "base_setup", "web"],
    "data": [
        "security/ir.model.access.csv",
        "views/res_config_settings_views.xml",
        "views/test_page_templates.xml",
    ],
    "external_dependencies": {
        "python": ["PyJWT", "cryptography", "requests"],
    },
    "installable": True,
    "application": False,
    "auto_install": False,
}
