# What this plugin relies on

Target: Jellyfin Server 12.2.0 / `net10.0`

| Topic | What the plugin does |
|---|---|
| Packages | Builds against `Jellyfin.Controller` and `Jellyfin.Model` 12.2.0 |
| Dashboard page | Uses Jellyfin's plugin page API (`IHasWebPages`) |
| Sign-in routes | Classifies password and Quick Connect routes. Playback routes are not classified |
| Reject before the handler | Middleware can return 403 or 429 before the rest of the pipeline |
| Jellyfin lockout counter | Read only. The plugin does not write `InvalidLoginAttemptCount` and does not treat its own 429 as protection of that counter |
| Storage | JSON under the plugin configuration directory. `jellyfin.db` is not written |
| Client address | `X-Forwarded-For` is trusted only from a known proxy, and only when that option is on |
| Login page | The captcha script is injected into the HTML response. Files on disk are not edited |
| Proxy files | The edge snippet is text to copy. Nginx, Caddy, and Cloudflare are not edited |
