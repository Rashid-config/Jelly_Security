# Changelog

## 0.21.1.0 — 2026-10-13 (first public release)

First public release. The dashboard is split into 8 tabs — Dashboard (live now),
Activity (all saved records and the attack timeline), Sign-in (sign-in defenses),
Detection (pattern detectors + API scan watch), Addresses, Sessions, Edge, and More.
The "Last 24 hours" report can be saved as a text file from the Dashboard.
Community infrastructure: issue templates, Dependabot, private vulnerability
reporting, code scanning, and secret scanning.

### Fixed

- **Failure counter scope**: a `401`/`403` on an observed admin or session route no longer counts as a failed sign-in. A legitimate client polling `GET /Sessions` without permission could accumulate enough "failures" to trigger an automatic ban. Only credential paths (password sign-in, Quick Connect, password reset) feed the counter now.
- **Redacted backups could not be restored** when the source config had a webhook URL: the `(redacted)` placeholder failed the SSRF check and the whole import was refused. The check now runs only when secrets are actually present in the file.
- **Persistence narrowed by a single corrupt file**: one unreadable JSON store file disabled writes for all files (bans included). Corruption now marks only that file read-only.
- **Lost tail of the event/address logs on shutdown**: debounced writes flushed on a timer only; a restart could drop the last ~5s of events and ~30s of known-address updates. A hosted service now flushes both on graceful shutdown.
- **Stale write race in the store**: snapshot and file write were not serialized together, so a later mutation's write could land before an earlier snapshot's and lose an entry on disk.
- **Client list gap**: `Jellyfin Media Player` and `Jellyfin Mobile` in the authorization `Client=` field were not recognized as apps and could be challenged for CAPTCHA when challenge-unknown was enabled.
- **Report endpoint** rejected large `hours` values with an error instead of clamping.
- **Geo lookup resilience**: an unreadable configured geo file threw through the report path; it now fails soft. Geo counters use atomic increments.
- Edge channel observations now push a live dashboard notification like other recorded events.

**Tests**: 376 passing, 0 warnings, 0 errors
**Target**: Jellyfin Server 12.2.0, .NET 10

## 0.21.0.0 — 2026-10-12

### Added

- **Liftable API scan slow-downs.** The dashboard status now returns the list of recon-limited addresses (address + seconds left) instead of just a count. "Active enforcement" shows each slowed address with an **End slow-down** button backed by a new `POST /JellySecurity/recon/clear` endpoint.
- API-scan events appear in the attack timeline as **Scan** steps (previously lumped under Attempt).

### Fixed

- **Missing live notifications**: automatic IPv6 /64 prefix bans and honeypot instant bans now push a live dashboard notification like every other ban path.
- **Timeline risk ranking**: the rank table looked for `Medium` while every event stores `Moderate`, so Moderate-risk stories never surfaced a highest band. Both spellings are now accepted.
- **Backup schema drift**: export/preview/restore stamped and accepted only schema 5 while the configuration schema is 8. All three now use a single `PluginConfiguration.CurrentSchemaVersion` constant, so restores stamp the current schema and backups from a newer build are refused cleanly.
- **Active enforcement button label**: rows read `r.action` while the data lives on `r.lift.action`, so blocked addresses showed "End pause" instead of "Lift block". Fixed.
- Removed `BoundedMap.AddOrUpdate` — unused, and it enqueued the key on every update, growing the insertion queue without bound.

**Tests**: 361 passing, 0 warnings, 0 errors
**Target**: Jellyfin Server 12.2.0, .NET 10

## 0.20.0.0 — 2026-10-12

### Added

- **API scan watch (per-endpoint rate limiting, opt-in).** Detects reconnaissance before a sign-in attack: a scanner probing `/Users`, `/Items`, `/Library`, `/System/Info`, and other enumeration endpoints now shows up in the plugin's own records.
  - `ReconPathClassifier` — an allowlist of collection/enumeration first-segment roots. Playback roots (`Videos`, `Audio`, `web`, `socket`) are never on the list. Per-item routes are excluded by GUID-shaped segments and an exact-match set of deep endpoints (`Images`, `Stream`, `Download`, `Subtitles`, `PlaybackInfo`, `Playing`, `Progress`). Depth capped at four segments.
  - `ReconWindow` — a sliding window per address counting failed (4xx) responses, unauthenticated requests, and distinct paths. Bounded map of 2000 addresses; all structures prune with the window.
  - `ReconPolicy` — pure threshold and enforcement checks, unit-testable.
  - Two detection rules: enough failed requests in the window (dominant signal — a scanner without a token collects 401s), or heavy unauthenticated volume across many distinct paths (separates enumeration from a client retrying one endpoint).
  - Crossing the threshold once per episode writes a **Reconnaissance** event, folds an `api_recon` signal into the incident system, pushes a live dashboard notification, and can fire the webhook.
  - **Slow down scanners** (off): on crossing, the middleware answers enumeration endpoints with `429` + `Retry-After` for a configurable cooldown. Requires a verified address, no exception class, and both options on. Sign-in and playback are never limited. Admin, monitoring, and trusted networks can never be rate-limited.
- Settings schema 8 (`ReconWatchEnabled`, `ReconEnforce`, `ReconWindowMinutes` 5, `ReconFailedThreshold` 30, `ReconUnauthThreshold` 120, `ReconDistinctPathMin` 15, `ReconCooldownMinutes` 10 — all off/conservative).
- Dashboard status now reports `reconWatchEnabled`, `reconEnforce`, and `reconLimited` (addresses currently rate-limited).
- 81 new tests covering path classification boundaries, window expiry/counters/caps, report-flag episodes, threshold rules, enforcement gates, and retry-after math.

**Tests**: 359 passing, 0 warnings, 0 errors
**Target**: Jellyfin Server 12.2.0, .NET 10

## 0.19.0.0 — 2026-10-12

### Added

- **Device fingerprinting (opt-in).** The client classifier now parses the Jellyfin authorization header (`MediaBrowser Client="...", Device="...", DeviceId="...", Version="..."`) with a new `DeviceFingerprint` parser. When the new "Require a real device ID for app classification" option is on, a client that claims to be a TV or mobile app — in User-Agent or in the Client field — but sends no `DeviceId` is downgraded to `Unknown` instead of `App`. Combined with *Block unrecognized clients too*, a bot that spoofs a TV User-Agent is challenged like a browser. Off by default so that older or custom clients without a `DeviceId` are not challenged along with the bots.
- Settings schema 7 (`StrictDeviceFingerprint`, default off).
- 17 new tests covering header parsing, quoted/unquoted fields, missing fields, strict-mode downgrade, and non-strict backwards compatibility.

**Tests**: 278 passing, 0 warnings, 0 errors
**Target**: Jellyfin Server 12.2.0, .NET 10

## 0.18.0.0 — 2026-10-12

### Added

- **Live dashboard via Server-Sent Events.** The dashboard now updates instantly when a sign-in event, ban, or incident fires — no 30-second wait. The frontend opens an EventSource connection to `GET /JellySecurity/stream` and refreshes the relevant sections on each notification. Falls back to 30-second polling if SSE is unavailable (e.g. a proxy that buffers responses).
- `SecurityEventHub` — a pub/sub hub that pushes live notifications to all connected SSE clients. Each client gets its own channel so one slow client does not block others.
- `LiveNotification` — a small payload (type, summary, timestamp) sent to the frontend as a "refresh now" signal.
- The engine publishes notifications on: sign-in events, manual ban add/remove, automatic ban.
- 5 new tests covering publish/subscribe, multiple subscribers, timestamps, and rapid publishes.

**Tests**: 261 passing, 0 warnings, 0 errors
**Target**: Jellyfin Server 12.2.0, .NET 10

## 0.17.0.0 — 2026-10-12

### Added

- **Attack timeline.** A new dashboard section groups failed and blocked sign-in attempts by source address into chronological attack stories. Each story shows the sequence of attempts, detected patterns, and any ban applied — so an administrator reads what happened from start to finish instead of scrolling a flat list. Read-only, built on demand from existing events, incidents, and bans. No extra files written.
- `TimelineBuilder` — correlates events, incidents, and bans into attack stories grouped by address.
- `GET /JellySecurity/timeline` — admin endpoint returning up to 50 stories, each with up to 100 steps.
- 18 new tests covering grouping, ban linking, CIDR matching, chronological ordering, risk bands, and limits.

**Tests**: 256 passing, 0 warnings, 0 errors
**Target**: Jellyfin Server 12.2.0, .NET 10

## 0.16.0 — 2026-10-12

### Added

- **Challenge unrecognized clients.** A new CAPTCHA option, "Block unrecognized clients too," requires a valid challenge token from clients with no recognizable User-Agent. Closes the path for bots that send no UA at all. Recognized TV apps stay exempt because they cannot render the widget. Off by default.
- **Automatic IPv6 /64 prefix bans.** A new automatic-ban option, "Ban the /64 prefix for IPv6 addresses," pauses the whole /64 network containing a failing IPv6 address instead of skipping the ban. A /64 is the typical end-user allocation, so this contains a client that rotates addresses inside its subnet. Off by default — prefix bans are broader than single-address bans.
- `BanKind.AutomaticPrefix` — a new ban kind for automatic IPv6 prefix bans, enforced under the same automatic-enforcement gate as `AutomaticTemporary` and `Progressive`.
- `Ipv6Prefix` helper — computes the CIDR prefix for an IPv6 address at any prefix length.
- `CaptchaChallengeUnknown` and `AutomaticIpv6PrefixBan` configuration fields. Schema version bumped to 6.

**Tests**: 218 passing, 0 warnings, 0 errors
**Target**: Jellyfin Server 12.2.0, .NET 10

## 0.15.1 — 2026-10-11

### Fixed

- **Detail tables stay readable.** Sign-in, ban, incident, and session tables no longer crush every cell onto multiple lines. Short columns (time, result, risk, name, address) hold one line; the last text column wraps naturally; the table gains a horizontal scrollbar instead of squeezing when space runs out.

**Tests**: 202 passing, 0 warnings, 0 errors
**Target**: Jellyfin Server 12.2.0, .NET 10

## 0.15.0 — 2026-10-11

### Overview

Country blocks: an Addresses-tab table that blocks sign-in attempts whose address matches a country row the administrator lists. Each row is a name plus editable CIDR ranges — fill a row from the local geo file configured in the More tab, or paste a range list by hand. Rows enforce like manual bans, so admin and monitoring networks are never blocked, and nothing happens until a row is on and "Enforce the addresses I block" is on.

**Tests**: 202 passing, 0 warnings, 0 errors
**Target**: Jellyfin Server 12.2.0, .NET 10

---

### Added

- `GeoBlockPolicy` — matches a sign-in address against enabled country rows via `CidrMatcher`. Invalid entries are ignored, never thrown.
- `GeoBlockRule` — one row: name, editable ranges text, on/off. Stored in plugin configuration so backup/restore carries it automatically.
- `BanKind.Geo` — a matched row produces a transient ban record, so blocks appear in events as "country block" with the row's name.
- `GET /JellySecurity/geo/lookup?name=` — reads the configured local geo file and returns its ranges for one country name; powers the per-row **Fill** button.
- Addresses tab: a "Block sign-in from countries I name" section with add/remove rows and a fill-from-geo-file button.

### Enforcement semantics

- A matched row blocks sign-in the same way a manual ban does: the request is rejected before Jellyfin sees it, with a clear event reason.
- Admin and monitoring networks are never geo-blocked — the same exception policy that protects manual bans applies, so an administrator cannot lock themselves out with a broad range.
- The feature needs no download and no external service. The only data source is the local geo CSV the administrator already can point at.

## 0.14.0 — 2026-10-11

### Overview

Initial public release of Jelly Security for Jellyfin 12.2. The plugin watches sign-in, keeps its own records, and can slow, pause, or block sign-in traffic when an administrator enables those options on. Jellyfin still checks the password — the plugin does not replace users, passwords, or sessions, and playback is never classified, delayed, or stopped.

This release ships 6 sign-in controls (password delay, account cooldown, lockout watch, browser challenge, honeypot ban, Quick Connect protection), 6 pattern detectors (brute force, distributed, spray, enumeration, honeypot, admin target), manual and automatic IP bans with proxy trust, session watch with non-playing device sign-out, an edge proxy snippet generator (Nginx, Caddy, Cloudflare), a block-list channel for proxy sync, webhook alerts with SSRF protection, and backup/restore with secret redaction. The dashboard shows live status, active enforcement, and a full audit log.

**Tests**: 192 passing, 0 warnings, 0 errors
**Target**: Jellyfin Server 12.2.0, .NET 10

---

### Critical security fixes

#### Webhook SSRF — hostnames now DNS-resolved

**Before**: The webhook URL validator checked IP literals only. A hostname like `http://metadata.google.internal/` passed validation because the code skipped DNS resolution to "avoid TOCTOU races."

**After**: Hostnames are now DNS-resolved and every returned IP must be public. A `ConnectCallback` on the HTTP client re-validates the resolved IP at socket-open time, closing the TOCTOU window entirely. If DNS returns a private, loopback, or link-local address at any point — validation or connection — the request is aborted.

**Files**: `WebhookPublisher.cs`

#### CAPTCHA hostname binding made mandatory

**Before**: The `hostname` field in the reCAPTCHA/Turnstile siteverify response was optional. If it was missing, verification passed. An attacker could replay a token from a different site.

**After**: The `hostname` field is now mandatory. A missing, null, or non-string `hostname` is rejected as `CaptchaCheck.Rejected`. Both Google reCAPTCHA and Cloudflare Turnstile return this field on every successful verification, so a missing field always indicates a malformed or suspicious response.

**Files**: `RecaptchaVerifier.cs`

#### XFF chain poisoning — rightmost non-proxy is the client

**Before**: The proxy trust validator took the **first** (leftmost) hop in `X-Forwarded-For` as the client address. An attacker behind a trusted proxy could inject a fake address at the left of the chain, poisoning automatic bans toward an innocent IP.

**After**: The validator now walks the chain right-to-left, skipping any hop that belongs to `KnownProxies`. The first non-proxy address from the right is the client. If any non-proxy hop remains to the left of the chosen client, the chain is marked ambiguous (`SourceTrust.Warning`), so automatic bans stay off. This matches the nginx `$proxy_add_x_forwarded_for` pattern.

**Files**: `ProxyTrustValidator.cs`

---

### Medium hardening

#### Honeypot fail-safe

`HoneypotNameMatchesUser` returned `true` on exception, silently disabling the honeypot instant ban on any transient user-manager failure. It now returns `false` (fail-safe for the honeypot, not for the ban) and logs the exception. The ban stays armed when the lookup fails.

**Files**: `SecurityEngine.cs`

#### Slow-loris protection

The password delay ceiling was 30 seconds with no limit on concurrent delayed connections. An attacker could open many connections and hold each for 30s, exhausting sockets. The ceiling is now 10 seconds, and a maximum of 64 connections may be delayed simultaneously. When the limit is reached, further delays are skipped and the request continues to Jellyfin immediately.

**Files**: `LoginDelayPolicy.cs`, `AuthGuardMiddleware.cs`

#### Incident snapshot defensive copies

`IncidentSnapshot()` returned the same object references as the live list. A reader serializing a snapshot could race with the aggregator mutating `Count`, `LastUtc`, and `RiskBand` on the same `SecurityIncident`. Snapshots now return `Clone()` copies, so readers and writers never share mutable state.

**Files**: `SecurityIncident.cs`, `SecurityStore.cs`

#### BoundedMap thread safety

Two threads racing through `GetOrAdd` could both enqueue the same key and both trigger eviction, causing duplicate entries and potential capacity overflow under high concurrency. All mutation (insert + evict) is now serialized under a lock with a double-check inside.

**Files**: `BoundedMap.cs`

---

### Dashboard reason column — actual block cause

The dashboard's "Reason" column showed the risk-assessment explanation ("No threat detector fired.") for every event, including blocked requests. An admin seeing `Blocked` with `No threat detector fired` had no idea why. The middleware now passes a specific, human-readable `blockReason` for every block path:

| Block type | Reason text |
|---|---|
| CAPTCHA (no token) | Browser sign-in blocked: no CAPTCHA token provided. |
| CAPTCHA (rejected) | Browser sign-in blocked: CAPTCHA token was rejected by the provider. |
| Cooldown | Sign-in paused by plugin cooldown for this username (Ns remaining). |
| Manual ban | Sign-in blocked by manual ban. Active ban matches this address. (Ns remaining) |
| Progressive ban | Sign-in blocked by progressive ban (strike 2). (900s remaining) |
| Admin restriction | Admin route blocked: this address is outside the configured Admin Networks. |
| Failed | Jellyfin rejected this sign-in attempt. (+ detector context) |
| Succeeded | Sign-in accepted by Jellyfin. (+ detector context) |

**Files**: `AuthGuardMiddleware.cs`, `SecurityEngine.cs`

---

### Dashboard overhaul

- **Auto-refresh**: Meters and live data update every 30 seconds without a manual page reload.
- **"Last updated" timestamp**: Shows when the data was last fetched.
- **Color-coded meter cards**: Red (alert), yellow (warn), green (ok) based on activity levels.
- **Timestamps formatted to local time**: Was raw ISO 8601, now `toLocaleString()`.
- **Ban list with Remove buttons**: Each active ban has a Remove button with a confirm dialog. Ended bans are visually distinct (dashed border, 45% opacity, no Remove button).
- **`loadEvents` race fixed**: Removed the double-request race condition on filtered views.
- **`parseInt` NaN fix**: Replaced with `fieldInt()` that falls back to the current value on empty/invalid input.
- **Post-save refresh**: `loadStatus()` is called after save so meters reflect new settings immediately.
- **Secret fields cleared after save**: `CaptchaSecret` and `EdgeSharedKey` are emptied after save.
- **`loadStatus` catch handler**: Now shows "Could not reach the plugin" instead of silently swallowing errors.
- **Emergency mode**: Added to the Mode dropdown (was missing from UI but present in code).

---

### Sign-in tab

- **Honeypot gate fixed**: The decoy name field was hidden behind the instant-ban checkbox. The detector uses the name even without the ban, so the admin could not set a name without enabling the ban first. The name field is now always visible.
- **CaptchaState indicator**: A new status line shows whether the captcha is ready (provider + valid site key) or incomplete, updating live as the admin types.
- **HoneypotState live update**: The honeypot state text now recomputes from the current form values as the admin types, before saving.
- **ClearCooldownButton feedback**: Shows a success/failure message and clears the input field after the action.

---

### Addresses tab

- **AddBanButton UX**: Trims target, validates minutes (rejects NaN/negative), shows success message, clears all fields after success.
- **Ban list visual distinction**: Active bans have solid borders and red tags. Ended bans have dashed borders and 45% opacity. Each ban shows its expiry time (formatted to local time) or "no expiry".
- **Remove confirm**: `confirm()` dialog before deleting a ban.
- **Placeholder**: Address field now has `placeholder="e.g. 203.0.113.5 or 10.0.0.0/24"` and a description.

---

### Sessions tab

- **Session list as table**: Converted from `<pre>` with pipe-delimited text to a proper HTML table (Name, Device, Address, Playback, Title, Why).
- **Clearer reason text**: "Signed in from a new address" instead of "new address", "Too many sessions at once" instead of "many sessions".
- **CloseSessionsButton**: Trims input, clears field after success, confirms before signing out devices, shows "A username is required." when empty.
- **ObserveSessions description**: Added a full description explaining what it records and what it does not.

---

### Edge tab

- **Copy feedback**: "Copied to clipboard." for 2 seconds after successful copy, or "Could not copy" on failure.
- **Scrollable snippet**: `max-height: 24rem` with `overflow: auto` and a bordered box.
- **Edge channel gated**: EdgeRestrictToTrustedPeers and EdgeSharedKey are now behind the EdgeChannelEnabled checkbox.
- **Descriptions**: Full descriptions for EdgeChannelEnabled, EdgeRestrictToTrustedPeers, and the snippet.
- **"Save first" note**: The snippet reflects saved settings, not unsaved form changes.

---

### More tab

- **Webhook gated**: Webhook URL field is now behind the WebhookEnabled checkbox.
- **Webhook URL label**: Was "(https)" but HTTP is allowed. Changed to "(http or https, public address only)" with SSRF description.
- **RestoreBackup confirm**: `confirm()` before applying, rejects empty input, warns that secrets on the server are kept.
- **BackupJson placeholder**: Added placeholder example and a description of what the backup includes.
- **AlertCooldownMinutes description**: Explains it prevents alert flooding.
- **PreviewBackup formatting**: Bullet points for each change, clear "Nothing has been applied yet" line.

---

### UX overhaul (all tabs)

- **Tab hints**: Each tab opens with a one-line description of its contents.
- **Banner styling**: The mode banner has a subtle background and rounded border.
- **Sticky save bar**: The Save button sticks to the bottom of the viewport with a blurred backdrop.
- **Info rows**: DelayCounters, CooldownList, LockoutList converted from `<pre>` to structured label: value rows.
- **EventList table**: Converted from `<pre>` to a proper HTML table.
- **Details/summary styled**: Bordered box, rounded corners, hover effect instead of browser default.

---

### Low / cleanup

- **Dead cookie removed**: `CaptchaChallenge` cookie was set but never read. Removed entirely.
- **AuthPathClassifier precision**: `Matches` now requires root-level path matching, preventing `/foo/Users/AuthenticateByName` from being classified as a password path.
- **Edge rate-limit normalization**: Uses `IpNormalizer` for the peer address key.
- **Event write debouncing**: `events.json` writes debounced to once per 5 seconds.
- **`.gitignore` hardened**: Added `.env`, `secrets.json`, `test-credentials.json` patterns.
- **Version sync**: `manifest.json`, `build.yaml`, `Directory.Build.props` updated to 0.14.0.0.

---

