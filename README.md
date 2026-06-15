# UMS Auth - Odoo Module

Odoo addon for SSO authentication & authorization via UMS (User Management System).

## Install

1. Copy `ums_auth` folder ke `addons/` directory Odoo
2. Install Python dependencies: `pip install PyJWT cryptography requests`
3. Restart Odoo, update apps list, install "UMS Authentication"

## Configure

Settings → General Settings → UMS:

| Field | Value | Keterangan |
|-------|-------|------------|
| UMS Base URL | `https://ums.yourserver.com` | URL server UMS |
| UMS App ID | `odoo-app` | App ID yang terdaftar di UMS |
| UMS Callback URL | `https://your-odoo.com/ums/callback` | Callback URL Odoo ini |
| Default Groups | `base.group_user,stock.group_stock_user` | Groups untuk user yang auto-created (comma-separated XML IDs) |

> Pastikan callback URL terdaftar di UMS Admin.

## Login Flow

```
User → /ums/login → UMS → Keycloak → /ums/callback?token=...
                                            │
                                            ▼
                                      Validate JWT
                                            │
                                            ▼
                              Cari Odoo user by email
                                    │              │
                                    │ Ada          │ Tidak ada
                                    ▼              ▼
                                  Login      Auto-create user:
                                              • login = email
                                              • name = dari token
                                              • groups = dari config
                                              • password = None (SSO only)
                                              • company = default
                                                    │
                                                    ▼
                                                  Login
```

User yang di-auto-create **tidak punya password** — hanya bisa login via UMS SSO. Tidak perlu maintain user management di Odoo.

## Usage

### SSO Login

User akses `/ums/login` → redirect ke UMS → Keycloak → kembali ke Odoo dengan session aktif.

### Controller Decorators

```python
from odoo import http
from odoo.http import request
from odoo.addons.ums_auth import auth, require, require_role, get_user, has_permission

class MyController(http.Controller):

    @http.route('/api/profile', type='json', auth='none')
    @auth
    def get_profile(self, **kwargs):
        user = get_user()
        return {'email': user['email'], 'modules': user['modules']}

    @http.route('/api/items', type='json', auth='none')
    @require('inventory', 'read')
    def get_items(self, **kwargs):
        return {'items': [...]}

    @http.route('/api/items/create', type='json', auth='none')
    @require('inventory', 'write')
    def create_item(self, **kwargs):
        return {'status': 'created'}

    @http.route('/api/admin', type='json', auth='none')
    @require_role('inventory', 'admin')
    def admin_action(self, **kwargs):
        return {'status': 'ok'}
```

### Helper Functions

```python
from odoo.addons.ums_auth import get_user, has_permission, has_role, has_module

# Di mana saja (controller, model method, wizard, dll)
user = get_user()                          # dict or None
can_write = has_permission('inventory', 'write')  # bool
is_admin = has_role('inventory', 'admin')         # bool
has_inv = has_module('inventory')                  # bool
```

### Model Mixin

```python
from odoo import models

class StockPicking(models.Model):
    _inherit = ['stock.picking', 'ums.access']

    def action_confirm(self):
        self.ums_require('inventory', 'write')  # raises AccessDenied if no permission
        return super().action_confirm()

    def action_delete(self):
        if not self.ums_can('inventory', 'delete'):
            raise UserError("You don't have delete permission")
        return super().unlink()
```

### Mixin API

| Method | Description |
|--------|-------------|
| `self.ums_can(module, perm)` | Check permission, returns bool |
| `self.ums_has_role(module, role)` | Check role, returns bool |
| `self.ums_require(module, perm)` | Check or raise AccessDenied |
| `self.ums_require_role(module, role)` | Check or raise AccessDenied |

## Routes

| Route | Description |
|-------|-------------|
| `/ums/login` | Redirect to UMS SSO |
| `/ums/callback` | Handle UMS callback, create session |
| `/ums/logout` | Logout from Odoo + UMS |

## Session Data

After login, the following is stored in `request.session`:

```python
request.session['ums_user']          # decoded JWT claims
request.session['ums_token']         # raw JWT
request.session['ums_refresh_token'] # refresh token
```
