# UMS Auth - Odoo 17 Module

Odoo 17 addon for SSO authentication & authorization via UMS (User Management System).

## Compatibility

| Odoo Version | Module Version | Branch |
|---|---|---|
| 17.0 | 17.0.1.0.0 | `17.0` |

## Requirements

- Odoo 17.0
- Python 3.10+
- PyJWT >= 2.0
- cryptography >= 41.0
- requests (bundled with Odoo)

## Install

1. Copy `ums_auth` folder ke `addons/` directory Odoo
2. Install Python dependencies:
   ```bash
   pip install PyJWT cryptography requests
   ```
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

## How It Works

### Authentication Flow

```
User → /ums/login → UMS → Keycloak → /ums/callback?token=...&refresh_token=...
                                            │
                                            ▼
                                      Validate JWT (JWKS)
                                            │
                                            ▼
                              Cari Odoo user by email
                                    │              │
                                    │ Ada          │ Tidak ada
                                    ▼              ▼
                              Store token    Auto-create user:
                              on user          • login = email
                                    │          • name = dari token
                                    │          • groups = dari config
                                    │          • password = None (SSO only)
                                    │                │
                                    ▼                ▼
                              session.authenticate(db, login, token)
                                            │
                                            ▼
                                    Odoo session aktif → /web
```

### Session Authenticate (Odoo 17)

Module ini menggunakan pattern yang sama dengan `auth_oauth` bawaan Odoo 17:

1. Token UMS disimpan di field `ums_access_token` pada `res.users`
2. `_check_credentials()` di-override untuk menerima token sebagai password
3. `request.session.authenticate(db, login, token)` dipanggil seperti biasa
4. Session valid dan aman karena `_get_session_token_fields()` menyertakan `ums_access_token`

User yang di-auto-create **tidak punya password** — hanya bisa login via UMS SSO.

## Usage

### SSO Login

User akses `/ums/login` → redirect ke UMS → Keycloak → kembali ke Odoo dengan session aktif.

### Controller Decorators

```python
from odoo import http
from odoo.http import request
from odoo.addons.ums_auth import auth, require, require_role, require_module
from odoo.addons.ums_auth import get_user, has_permission

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

    @http.route('/api/dashboard', type='json', auth='none')
    @require_module('dashboard')
    def dashboard(self, **kwargs):
        return {'status': 'ok'}
```

### Helper Functions

```python
from odoo.addons.ums_auth import (
    get_user, has_permission, has_role, has_module,
    get_modules, get_permissions, get_roles,
    validate_token, validate_token_remote, refresh_token,
    invalidate_jwks_cache,
)

# Di controller, model, wizard, dll
user = get_user()                                # dict or None
can_write = has_permission('inventory', 'write') # bool
is_admin = has_role('inventory', 'admin')        # bool
has_inv = has_module('inventory')                 # bool

# Detailed info
modules = get_modules()                          # list of module dicts
perms = get_permissions('inventory')             # ['read', 'write']
roles = get_roles('inventory')                   # ['admin', 'viewer']

# Advanced: validate token manually
claims = validate_token(token_string)            # dict
claims = validate_token_remote(token_string)     # via UMS server

# Force JWKS cache refresh (after key rotation)
invalidate_jwks_cache()
```

### Model Mixin

```python
from odoo import models

class StockPicking(models.Model):
    _inherit = ['stock.picking', 'ums.access']

    def action_confirm(self):
        self.ums_require('inventory', 'write')  # raises AccessDenied
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
| `self.ums_has_module(module)` | Check module access, returns bool |
| `self.ums_require(module, perm)` | Check or raise AccessDenied |
| `self.ums_require_role(module, role)` | Check or raise AccessDenied |
| `self.ums_require_module(module)` | Check or raise AccessDenied |

## Routes

| Route | Method | Description |
|-------|--------|-------------|
| `/ums/login` | GET | Redirect to UMS SSO |
| `/ums/callback` | GET | Handle UMS callback, create session |
| `/ums/logout` | GET | Logout from Odoo + UMS |
| `/ums/refresh` | POST (JSON) | Refresh token and update session |

## Session Data

After login, the following is stored in `request.session`:

```python
request.session['ums_user']          # decoded JWT claims
request.session['ums_token']         # raw JWT
request.session['ums_refresh_token'] # refresh token
```

## Token Refresh

The module provides `/ums/refresh` endpoint that can be called from frontend JS:

```javascript
// Auto-refresh before token expiry
const response = await fetch('/ums/refresh', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({jsonrpc: '2.0', method: 'call', params: {}})
});
```

## Security Notes

- UMS access token is stored on `res.users` record (field: `ums_access_token`)
- Field is restricted to `base.group_system` (admin only)
- Token is used as credential for `session.authenticate()` — same pattern as Odoo's `auth_oauth`
- When token changes (refresh), existing sessions are invalidated via `_get_session_token_fields`
- JWKS keys are cached for 1 hour with thread-safe refresh
- Stale cache fallback: if JWKS endpoint is unreachable, last known key is used

## Migration from 16.0

If upgrading from the 16.0 version:

1. The module now adds `ums_access_token` field to `res.users` (auto-migrated)
2. `request.session.authenticate()` now uses proper Odoo 17 pattern
3. New `security/ir.model.access.csv` added
4. New helper functions: `get_modules()`, `get_permissions()`, `get_roles()`, `validate_token_remote()`, `invalidate_jwks_cache()`
5. New decorator: `@require_module`
6. JWKS caching is now thread-safe

No breaking changes in the public API (decorators and helpers).

## Troubleshooting

| Issue | Solution |
|-------|----------|
| "UMS not configured" | Set UMS Base URL and App ID in Settings |
| "Invalid token" | Check UMS server is reachable, JWKS endpoint responding |
| User created but can't access menus | Adjust default groups in settings |
| Session lost after token refresh | Expected — new token invalidates old session token |
| JWKS fetch timeout | Check network connectivity to UMS server |
