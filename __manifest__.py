{
    "name": "UMS Authentication",
    "version": "16.0.1.0.0",
    "category": "Technical",
    "summary": "SSO authentication & authorization via UMS (User Management System)",
    "author": "Kodepik",
    "website": "https://github.com/taufiqtab/ums-odoo-sdk",
    "license": "LGPL-3",
    "depends": ["base", "web"],
    "data": [
        "views/res_config_settings_views.xml",
    ],
    "external_dependencies": {
        "python": ["PyJWT", "cryptography", "requests"],
    },
    "installable": True,
    "application": False,
    "auto_install": False,
}
