# v2.0 integrations

Defaults stay off. Nothing here replaces Jellyfin authentication.

| Feature | Status |
|---|---|
| Local risk score 0–100 | Display only. Not a calibrated standard. Geo never increases it. |
| Historical decay | 50% per 24 hours, in memory |
| Browser challenge | Optional and off by default. Choose Google reCAPTCHA v2 or Cloudflare Turnstile. Browser login and forgot-password forms show that provider's checkbox when both keys are saved. Jellyfin web files on disk are not edited. Apps and unknown clients are never challenged. Fail-open applies only when the selected provider cannot be reached. |
| Password delay | Optional and off by default. Password sign-in only. Default ladder 1s, 3s, 5s. Playback is not delayed. |
| Account cooldown | Optional and off by default. Pauses one username after a distributed spray, then expires. Does not disable the Jellyfin account. |
| Honeypot instant ban | Optional and off by default. One use of a decoy name that matches no Jellyfin user bans that verified IPv4 address. |
| Lockout watch | Optional and off by default. Reads each account's own Jellyfin lockout counter and warns when few attempts remain. Does not reset or change the counter. A limit of -1 or any non-positive limit is not a warning. |
| MFA | Not available |
| Edge channel | `GET /JellySecurity/edge/blocklist` and `POST /JellySecurity/edge/events` with a shared key. Does not write Nginx/Caddy files. |
| Edge paste snippet | Optional and off by default. Shows a Nginx, Caddy, or Cloudflare snippet for sign-in routes only. The plugin does not write those files. Playback is not listed. |
| Session watch | Optional and off by default. Alerts on a new sign-in address or too many concurrent sessions. The close button skips sessions that are playing. Nothing is logged out automatically. |
| External threat feeds | Not downloaded and not auto-applied |
| Local geo CSV | Optional enrichment |
| Reports | Plugin events only, with a data-quality note |
