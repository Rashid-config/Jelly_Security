# Jellyfin 12.2 authentication paths

Mapped from `v12.2` source. Playback routes are out of scope.

| Method | Path | Kind | Notes |
|---|---|---|---|
| POST | `/Users/AuthenticateByName` | Password | Primary sign-in for web, apps, and TV |
| POST | `/Users/{userId}/Authenticate` | Password | Obsolete, still present |
| POST | `/Users/AuthenticateWithQuickConnect` | Quick Connect | Completes a Quick Connect session |
| POST | `/QuickConnect/Initiate` | Quick Connect | Starts a code |
| POST | `/QuickConnect/Authorize` | Quick Connect | Approves a code |
| POST | `/Users/ForgotPassword` | Password reset | Observed only in v0.1 |

`HttpContext.GetNormalizedRemoteIP()` is what Jellyfin itself uses after Known Proxies. The plugin resolver is independent and must be proven against that helper before automatic IP bans are advertised.
