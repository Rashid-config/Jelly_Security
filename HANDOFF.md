# Jelly Security — Development Handoff Notes

> **Purpose**: Everything a maintainer or contributor needs before working on this plugin — what it is, how it is built, and where to look.

> **Last updated**: 2026-10-13 (v0.21.1.0 — 8-tab dashboard, issue templates, Dependabot, security policy)
> **Status**: 376 tests passing, 0 warnings, 0 errors. Plugin deployed and verified on a live Jellyfin 12.2 server.

---

## 1. Project Identity

| Field | Value |
|---|---|
| **Name** | Jelly Security |
| **Type** | Jellyfin 12.2 plugin (.NET 10 / `net10.0`) |
| **GUID** | `8b4e2c1a-6d3f-4a19-9e2b-7c5f1d8a0b34` |
| **Repository** | `https://github.com/Rashid-config/Jelly_Security.git` |
| **License** | GPL-3.0-or-later |
| **Current version** | 0.21.1.0 |
| **Target** | Jellyfin Server 12.2.0, `net10.0` |
| **Build command** | `dotnet test Jellyfin.Plugin.JellySecurity.slnx -c Release` |
| **Output DLL** | `src/Jellyfin.Plugin.JellySecurity/bin/Release/net10.0/Jellyfin.Plugin.JellySecurity.dll` |
| **Test count** | 376 (all passing, 0 warnings, TreatWarningsAsErrors=true) |

## 2. Mission and Philosophy

### What this plugin does
Jelly Security is a **sign-in protection layer** for Jellyfin servers. It:
- Watches sign-in attempts (password, Quick Connect, forgot-password)
- Keeps its own JSON records (never writes `jellyfin.db`)
- Can slow, pause, or block sign-in traffic when an admin enables those options
- Jellyfin still checks the password — the plugin does NOT replace authentication

### What this plugin does NOT do
- Does NOT touch playback (streaming, progress, play commands)
- Does NOT replace users, passwords, or sessions
- Does NOT disable Jellyfin users
- Does NOT edit firewall, Nginx, Caddy, or Cloudflare files
- Does NOT write Jellyfin's `InvalidLoginAttemptCount`
- Does NOT provide MFA/2FA

### The goal
Make this repo a **trusted, public security layer** for the Jellyfin community. It must:
1. Protect any Jellyfin server, not just one installation
2. Fail safely — a plugin error must never lock the administrator out
3. Never delay, classify, or stop playback
4. Be auditable and transparent

### Design principles (MUST follow)
- **Fail-safe**: If the plugin throws, the request continues to Jellyfin. A plugin error must never lock users out.
- **Playback is sacred**: Never classify, delay, or stop playback URLs.
- **No secrets in logs**: Passwords, tokens, captcha secrets, edge keys are never logged.
- **Monitor by default**: All enforcement features start OFF. Admin must explicitly enable them.
- **No `jellyfin.db` writes**: Plugin stores its own JSON files only.
- **Warnings are errors**: `TreatWarningsAsErrors=true`, `Nullable=enable`.
- **Comment discipline**: Keep comments accurate; do not churn or strip context.

## 3. Architecture Overview

### Request flow (sign-in)
```
Request → CaptchaPageMiddleware (injects CAPTCHA into HTML)
        → AuthGuardMiddleware (classifies path, decides action)
            → CAPTCHA check (if enabled, web browser)
            → Account cooldown check
            → IP ban check
            → Password delay
            → Request continues to Jellyfin
        → Observe result (Blocked/Failed/Succeeded/Unknown)
```

### Request flow (API recon surface)
```
Request on enumeration path (e.g. GET /Users)
        → AuthGuardMiddleware (AuthPathKind.None + ReconPathClassifier hit)
            → EvaluateReconLimit — 429 + Retry-After if inside cooldown
            → Request continues to Jellyfin
        → ObserveApiRequest — ReconWindow counts failure/unauth/breadth
            → crossing threshold → Reconnaissance event + api_recon incident
            → + cooldown (only with ReconEnforce, verified address, no exception)
```

### Source layout
```
src/Jellyfin.Plugin.JellySecurity/
  Plugin.cs                        ← Entry point + dashboard page registration
  PluginServiceRegistrator.cs      ← DI registration (SecurityStore, ProxyTrustValidator, CaptchaVerifier, SecurityEngine, IStartupFilter)
  PluginConstants.cs               ← GUID, Name, TargetJellyfinVersion
  Configuration/
    PluginConfiguration.cs         ← All settings (~90 properties, schema version 8)
    ProtectionMode.cs              ← MonitorOnly, Balanced, Strict, Custom, Emergency
  Integration/
    AuthGuardMiddleware.cs         ← Core middleware: classifies, blocks, observes
    AuthGuardStartupFilter.cs      ← Registers middleware at pipeline start
    AuthPathClassifier.cs          ← Maps Jellyfin 12.2 auth routes to kinds
    AuthPathKind.cs                ← None, Password, QuickConnect, PasswordReset, Admin, Session
    CaptchaPageMiddleware.cs       ← Injects CAPTCHA script into login HTML
    PluginFlushService.cs          ← IHostedService: flushes pending store writes on shutdown
  Api/
    SecurityDashboardController.cs ← Admin API under /JellySecurity (RequiresElevation)
    EdgeChannelController.cs       ← Anonymous edge API under /JellySecurity/edge (shared key)
    CamelJson.cs                   ← camelCase JSON serialization helper
  Storage/
    SecurityStore.cs               ← JSON file store: bans, events, audit, incidents, known-addresses
  Core/Engine/
    SecurityEngine.cs              ← Central decision point
    EnablementGate.cs              ← Two-step enablement for automatic IP bans
    AdminRestriction.cs            ← Partial admin-network gate (fail-open)
    ConfigBackup.cs                ← Export/import with secret redaction + SSRF check
    PostureAuditor.cs               ← Settings audit findings
    PostureFinding.cs
    SecurityEventHub.cs            ← SSE live notification hub for the dashboard
  Core/Policies/
    BanKind.cs                     ← AutomaticTemporary, Progressive, Manual, Cidr
    BanRecord.cs                   ← Ban storage model
    BanSchedule.cs                 ← Progressive ban ladder (5,15,60,1440 min)
    BanTargetValidator.cs         ← Rejects invalid CIDR and whole-internet
    ExceptionClass.cs              ← None, Loopback, Administrative, Trusted, Monitoring
    ExceptionPolicy.cs             ← Priority: Admin/Monitoring > Trusted/Loopback > None
    StrikeState.cs
  Core/Networking/
    CidrMatcher.cs                 ← IP/CIDR matching
    ClientIdentity.cs              ← Address, RemoteSocket, Trust, Reason, Forwarded info
    IpNormalizer.cs                ← Normalize IPv4-mapped IPv6, strip zones
    Ipv6Prefix.cs                  ← /64 grouping for analysis
    ProxyTrustValidator.cs        ← X-Forwarded-For trust logic
    SourceTrust.cs                ← Verified, Warning, Unknown
  Core/RateLimiting/
    AccountCooldownPolicy.cs      ← Plugin-owned username pause
    AccountCooldownTracker.cs
    AttemptWindow.cs               ← Sliding window counter
    BoundedMap.cs                  ← Capped map with FIFO eviction
    LoginDelayPolicy.cs            ← Password sign-in delay (1s, 3s, 5s)
    PasswordDelayTracker.cs
    TimedSet.cs                    ← Distinct keys in a sliding window
  Core/Detection/
    ThreatDetectors.cs             ← 7 detectors: brute force, distributed, spray, enumeration, stuffing, honeypot, admin targeting
    RiskEvaluator.cs               ← Combines signals, no double counting
    RiskScore.cs                   ← 0-100 local score with 24h decay
    AlertAggregator.cs             ← Incident grouping with cooldown
    ClientKindClassifier.cs       ← Web/App/Unknown from User-Agent + device fingerprint
    DeviceFingerprint.cs          ← Parses MediaBrowser authorization header (Client/Device/DeviceId)
    ClientKind.cs
    DetectorSignal.cs
    EventQuery.cs                  ← Filter + CSV export
    HistoricalRisk.cs
    HoneypotBanPolicy.cs          ← Instant ban for decoy name
    LockoutWatchPolicy.cs         ← Reads Jellyfin's own lockout counter (read-only)
    ObservationContext.cs
    ReconPathClassifier.cs        ← Allowlist of enumeration surface roots
    ReconPolicy.cs                ← Threshold + enforcement checks for the API scan watch
    ReconWindow.cs                ← Sliding window counters + 429 limit tracking
    PolicyAuditEntry.cs
    RiskAssessment.cs
    SecurityEvent.cs
    SecurityIncident.cs
    TextSanitizer.cs               ← Display (strip markup) + HtmlEncode (HTML entities) + CsvField
    WebhookPublisher.cs            ← Optional alert with SSRF protection
  Core/Captcha/
    CaptchaPolicy.cs               ← reCAPTCHA v2 / Cloudflare Turnstile policy
    CaptchaCheck.cs                ← Absent, Passed, Rejected, Unreachable
    CaptchaDecision.cs
    CaptchaLoginScript.cs          ← Injected JS
    CaptchaPageRewriter.cs        ← Decompress + inject into HTML
    LoginPageCache.cs             ← Prevent stale cached login pages
    RecaptchaKey.cs               ← Key validation (20-200 chars, A-Z a-z 0-9 _ -)
    RecaptchaVerifier.cs          ← Google siteverify
    TurnstileVerifier.cs          ← Cloudflare siteverify
    CaptchaVerifier.cs            ← Provider router
  Core/Edge/
    EdgeAccess.cs                  ← Shared key auth (constant-time compare)
    EdgeSnippet.cs                ← Nginx/Caddy/Cloudflare snippet builder
  Core/Sessions/
    SessionWatchPolicy.cs         ← New-address alerts, concurrent session alerts, KnownAddressBook
  Core/Geo/
    LocalGeoDirectory.cs          ← Local CSV lookup (no download)
    GeoBlockPolicy.cs             ← Optional country allow/block list
  Core/Reports/
    SecurityReport.cs             ← 24-hour report builder
    TimelineBuilder.cs            ← Groups events into per-attack stories
  Web/
    configPage.html               ← Dashboard page (embedded resource, English).
                                    8 tabs: Dashboard, Activity, Sign-in, Detection,
                                    Addresses, Sessions, Edge, More
tests/Unit/Jellyfin.Plugin.JellySecurity.Tests/
    376 tests total
```

### Key API routes
| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/JellySecurity/status` | Admin | Mode, health, counters, snapshots |
| GET | `/JellySecurity/events` | Admin | Filtered events |
| GET | `/JellySecurity/events.csv` | Admin | CSV export |
| GET | `/JellySecurity/timeline` | Admin | Attack stories grouped by address |
| GET | `/JellySecurity/stream` | Admin | SSE live notifications |
| GET | `/JellySecurity/bans` | Admin | List bans |
| POST | `/JellySecurity/bans` | Admin | Add manual ban |
| DELETE | `/JellySecurity/bans?target=` | Admin | Remove ban |
| GET | `/JellySecurity/report?hours=` | Admin | Time-window report |
| GET | `/JellySecurity/posture` | Admin | Settings audit |
| GET | `/JellySecurity/backup` | Admin | Export settings |
| POST | `/JellySecurity/backup/preview` | Admin | Preview import |
| POST | `/JellySecurity/backup/restore` | Admin | Apply import |
| POST | `/JellySecurity/cooldowns/clear` | Admin | End username cooldown |
| POST | `/JellySecurity/recon/clear` | Admin | End an API scan slow-down early |
| POST | `/JellySecurity/sessions/close-others` | Admin | Sign out idle sessions |
| GET | `/JellySecurity/snippet` | Admin | Edge proxy snippet text |
| GET | `/JellySecurity/edge/blocklist` | Edge key | Active bans as JSON |
| GET | `/JellySecurity/edge/deny.txt` | Edge key | Bans as Nginx/Caddy/Cloudflare text |
| POST | `/JellySecurity/edge/events` | Edge key | Record edge observation (rate-limited 60/min) |

### Storage files (under Jellyfin plugin config dir, `JellySecurity/`)
| File | Survives restart | Contents |
|---|---|---|
| `bans.json` | Yes | Manual and automatic bans |
| `events.json` | Yes | Security events (30 days / 20,000 cap) |
| `audit.json` | Yes | Policy changes (2,000 row cap) |
| `incidents.json` | Yes | Grouped alerts (2,000 cap) |
| `known-addresses.json` | Yes | Session watch addresses (32/user) |

In-memory only (cleared on restart): password-delay counters, account cooldowns, lockout notices, session notices, risk history, API scan windows and 429 limits.

## 4. Security Design

### Hardening history (audit findings, all fixed)

| # | Severity | Issue | Fix | Files |
|---|---|---|---|---|
| 1 | **Critical** | CAPTCHA bypass: attacker sends direct API request without loading login page (no cookie = no token = no block) | Removed `challengeIncluded` cookie bypass. Missing token always blocks web browser when enforcement is on. | `CaptchaPolicy.cs` |
| 2 | **Critical** | SSRF: webhook URL accepts `http://169.254.169.254/` (cloud metadata) | Added `IsPublicAddress()` checking loopback, private (RFC 1918), link-local, multicast, reserved. DNS resolution at validation and connection time. | `WebhookPublisher.cs` |
| 3 | **Critical** | XFF chain poisoning: rightmost non-proxy address is not validated | Rightmost non-proxy address is now the client. Proxy chain validated against Known Proxies. | `ProxyTrustValidator.cs` |
| 4 | **Medium** | BoundedMap random eviction lets attacker flood random keys to evict legitimate tracking | Changed to FIFO eviction via `ConcurrentQueue<string>`. | `BoundedMap.cs` |
| 5 | **Medium** | SecurityStore `File.WriteAllText` is not atomic (corruption on crash) | Atomic write: temp file + `File.Replace`/`File.Move`. | `SecurityStore.cs` |
| 6 | **Medium** | RecaptchaVerifier `HostMatches` returns `true` for empty host (token reuse from other site) | Returns `false` for empty/missing hostnames. Hostname binding is mandatory. | `RecaptchaVerifier.cs` |
| 7 | **Medium** | Edge `POST /edge/events` has no rate limit (flood with known key) | Added per-caller rate limit: 60/min using `BoundedMap<AttemptWindow>`. | `EdgeChannelController.cs` |
| 8 | **Medium** | HoneypotNameMatchesUser returns `true` on exception, disabling honeypot ban | Fail-safe: returns `false` on exception so the ban stays active. | `HoneypotBanPolicy.cs` |
| 9 | **Medium** | PasswordDelay holds connection up to 30 seconds (slow-loris risk) | Ceiling reduced to 10s. | `LoginDelayPolicy.cs` |
| 10 | **Medium** | AlertAggregator mutates shared `SecurityIncident` objects in the list | Returns defensive copies from `IncidentSnapshot()`. | `AlertAggregator.cs` |
| 11 | **Low** | Plugin version hardcoded as `"0.12.6.0"` in controller | Read from `typeof(Plugin).Assembly.GetName().Version`. | `SecurityDashboardController.cs` |
| 12 | **Low** | TextSanitizer only strips `<>` but not `& " '` (incomplete XSS prevention) | Added `HtmlEncode()` with full HTML entity encoding via `StringBuilder`. | `TextSanitizer.cs` |
| 13 | **Low** | KnownAddressBook writes to disk on every successful sign-in from new address | Debounced: flush at most once per 30 seconds. | `SecurityEngine.cs` |

### Known design gaps (documented, not bugs)
- Admin route map is partial (only a known set of user/system write routes)
- Unknown clients skip the challenge unless the opt-in "block unrecognized clients" option is on
- IPv6 /64 prefix bans exist but are opt-in (`AutomaticIpv6PrefixBan`)
- Edge route may still require Jellyfin authentication
- No MFA/2FA
- Country data never raises the risk score
- Plugin does not edit firewall/proxy files

## 5. The Login Page Decision

### Chosen approach: Strengthen the Middleware (NOT replace the login page)

**Why not replace the login page?**
- If the plugin has a bug, nobody can sign in — breaks the server
- TV/phone apps use their own UI, not the HTML page
- Jellyfin updates may change the API and break a replacement page
- Uninstalling the plugin must restore the original (complex)

**Why middleware?**
- Safe: never breaks any server
- Works with all clients (TV, phone, browser)
- Doesn't depend on Jellyfin's HTML structure
- Easy to revert (disable the plugin)

**Future enhancement (not started):** A `/JellySecurity/gate` intermediate page that appears before sign-in, presents a challenge, and issues a temporary token/cookie that the middleware checks. This would give deeper control without replacing Jellyfin's login. It needs careful handling of non-browser clients.

## 6. Build and Development

### Building the project
```powershell
# From the repo root:
dotnet test Jellyfin.Plugin.JellySecurity.slnx -c Release
```

### Key build settings (`Directory.Build.props`)
- `LangVersion=latest`
- `Nullable=enable`
- `ImplicitUsings=enable`
- `TreatWarningsAsErrors=true`
- `NoWarn=CS1591` (missing XML doc comments)
- Version: `0.21.1.0`

### CI (`.github/workflows/`)
- `build.yml`: builds and tests on every push/PR (`ubuntu-latest`, .NET 10)
- `release.yml`: on tag push `v*`, builds, tests, packages the zip, computes the MD5 checksum, creates the GitHub release with `softprops/action-gh-release@v3`, uploads the asset, and auto-updates `manifest.json`

## 7. Open Work (Prioritized)

Done already: device fingerprinting (`DeviceFingerprint.cs`), unknown-client challenge
(`CaptchaChallengeUnknown`), honeypot fail-safe, automated release pipeline, release
packaging with checksum + manifest, backup export/import through the dashboard,
issue templates, Dependabot, and a security policy.

### Shorter-term
1. Dashboard internationalization (Arabic UI) — the page is English-only today
2. Integration tests against a live Jellyfin server — coverage is unit-only today

### Longer-term ideas
3. `/JellySecurity/gate` intermediate challenge page — deeper control without
   replacing Jellyfin's login; needs care for non-browser clients
4. Progressive challenge (easy → hard → block)
5. Webhook signing (HMAC) for alert authenticity
6. Optional local IP reputation feed (loaded from disk, never downloaded)

## 8. Notes for Whoever Picks This Up

### What the project is for
- A public, community-trusted security plugin for Jellyfin
- Protect any Jellyfin server, not just one installation
- Fail safely — a plugin error must never lock the administrator out
- Never delay, classify, or stop playback
- No hidden behavior, no secret data collection

### Working conventions
- Commit messages describe the *why*, not just the *what*
- Commits are authored by the repository owner; keep bot attribution out of history
- Verify with a real build and test run before calling anything done

---

**End of handoff. Read `Jelly_Security.md` in the repo root for the full technical design document. Read `CHANGELOG.md` for version history. Read `docs/USER_GUIDE.md` for the user-facing guide.**
