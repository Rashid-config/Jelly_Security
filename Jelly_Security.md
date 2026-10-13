# Jelly Security

This file describes the repository as it is at version **0.21.1.0**. It is a guide to the code, the settings, and the limits. It is not a plan for features that are not here.

Jelly Security is a Jellyfin plugin. It watches sign-in, keeps its own records, and can slow, pause, or block some sign-in traffic when an administrator turns those options on. Jellyfin still checks the password. The plugin does not replace users, passwords, or sessions.

Playback is left alone. Streaming, progress, and play commands are not classified, delayed, or stopped by these controls.

## Project facts

| | |
|---|---|
| Plugin name on the dashboard | Jelly Security |
| Plugin id | `8b4e2c1a-6d3f-4a19-9e2b-7c5f1d8a0b34` |
| Built for | Jellyfin Server 12.2.0, `net10.0` |
| License | GPL-3.0-or-later |
| Repository | https://github.com/Rashid-config/Jelly_Security.git |
| Current version | 0.21.1.0 (`Directory.Build.props`, `build.yaml`, `manifest.json`) |
| Settings schema | 8. New fields use the defaults in code when an older file has no value. |

Jellyfin loads the plugin from its plugin folder. The build command is `dotnet test Jellyfin.Plugin.JellySecurity.slnx -c Release`. The assembly is `src/Jellyfin.Plugin.JellySecurity/bin/Release/net10.0/Jellyfin.Plugin.JellySecurity.dll`.

The plugin keeps its own JSON files. It does not write `jellyfin.db`. `manifest.json` is the catalog entry Jellyfin uses to find a release package. The checksum in that file is filled when a package is published.

## What you get after install

Jellyfin shows one dashboard page, **Jelly Security**, under the server menu. The page is in English.

It opens with what is happening now. Each following choice is a goal: slow password guesses, pause a sprayed name, warn before a Jellyfin lockout, notice an unfamiliar session, block an address, pause an address after repeated failures, ask the browser to confirm a person, treat a decoy name as enough, and copy a proxy limit. The numbers for a goal appear after that goal is turned on. Patterns, backups, and sign-in history stay folded on the same page.

The page reads and writes the plugin's own settings. It does not change Jellyfin's user lockout number.

Most switches start off. Turning a switch on in the form does nothing until the administrator saves.

## How a sign-in request is handled

Two pieces of middleware run at the start of the pipeline:

1. `CaptchaPageMiddleware` may add a verification widget to the browser login HTML.
2. `AuthGuardMiddleware` decides whether this request is a sign-in path, and what to do before Jellyfin handles it.

On a password sign-in the order is:

1. Browser verification, if that option is on and the client is a browser.
2. Account cooldown, if that option is on and this username is paused.
3. IP ban, if a ban matches and the rules allow it to be enforced.
4. Password delay, if that option is on and this address has recent failures.
5. The request continues to Jellyfin.

After Jellyfin responds, the plugin records the outcome. A block from the plugin (403 or 429) is stored as **Blocked**. It is not stored as a wrong password. A normal HTTP 401 or 403 from Jellyfin is **Failed**. A 2xx response is **Succeeded**. Anything else is **Unknown**.

The plugin does not read the password. It does not write passwords, tokens, or Quick Connect codes into its log.

These are the sign-in paths it knows:

| Method | Path | Treated as |
|---|---|---|
| POST | `/Users/AuthenticateByName` | Password |
| POST | `/Users/{id}/Authenticate` | Password |
| POST | `/Users/ForgotPassword` | Password reset. Verification can apply. Delay, cooldown, and ban do not use the password-delay path. |
| POST | `/Users/AuthenticateWithQuickConnect` | Quick Connect |
| POST | `/QuickConnect/Initiate` | Quick Connect |
| POST | `/QuickConnect/Authorize` | Quick Connect |

Quick Connect bans are a separate switch, off by default. Playback URLs are never in this list.

A small set of admin write routes can be limited to admin networks. That list is partial. The startup wizard is not treated as admin. See `docs/architecture/admin-paths-partial.md` and `docs/architecture/auth-paths-12.2.md`.

If the plugin throws while deciding, and the response has not started, the request continues to Jellyfin. A cancelled request does not continue.

## Addresses

The plugin does not trust `X-Forwarded-For` unless **Trust forwarded headers** is on and the socket address is in **Known proxies**. A chain of several proxies is treated as uncertain, and automatic IP bans stay off.

Four kinds of network can be listed as CIDR or single addresses:

- **Trusted** — home or other networks you trust. Manual bans still apply. Automatic bans do not.
- **Administrative** — outranks both manual and automatic bans.
- **Monitoring** — same priority as administrative.
- **Loopback** — `127.0.0.1` and `::1` are treated the same way as trusted for bans: manual bans can match, automatic bans do not.

`0.0.0.0/0`, `::/0`, and prefix length 0 are rejected. Addresses are parsed as real IP addresses, not as text search. IPv4-mapped IPv6 is stored as IPv4.

Automatic bans are IPv4 only by default. IPv6 can be banned by hand. An IPv6 /64 can be used as a label for analysis. When the **Automatic IPv6 /64 prefix ban** option is on, a failing IPv6 address pauses its whole /64 prefix instead of being skipped. The /64 is the typical end-user allocation, so this contains a client that rotates addresses inside its subnet. The option is off by default — prefix bans are broader than single-address bans.

## Modes

The mode dropdown has Monitor only, Balanced, Strict, Custom, and Emergency.

For automatic IP bans they collapse to one rule: those bans run only when the mode is not Monitor only, the automatic-ban switch is on, and the client address is verified. If forwarded headers are trusted, the known-proxy list must not be empty.

Emergency does one extra thing: it turns off the admin-network restriction. There is no separate emergency timer.

Other features (verification, delay, cooldown, honeypot ban, lockout watch, session watch, edge snippet) have their own switches. They do not wait for the mode to leave Monitor only.

## Sign-in controls

### Manual bans

On by default (`ApplyManualBans`). An administrator adds an IPv4 address, an IPv6 address, or a CIDR, with an optional duration and a reason. An empty duration is a ban with no expiry. Removing it deletes it from memory and from `bans.json`.

Manual bans do not apply to administrative or monitoring networks.

### Automatic IP bans

Off by default, and also off while the mode is Monitor only.

After 10 failed password sign-ins from one verified IPv4 address in 5 minutes, the plugin bans that address. The first ban is 5 minutes. Repeat bans follow 5, 15, 60, then 1440 minutes. After 7 quiet days the strike count fades. These numbers are settings.

For IPv6 addresses, the same failure counter applies, but no automatic ban is stored unless the **Automatic IPv6 /64 prefix ban** option is on. When it is on, the ban targets the /64 prefix instead of the single address, and the strike ladder works the same way.

The ban reason counts failed sign-ins. A honeypot hit does not also climb this ladder; it returns on its own path.

An untrusted address cannot receive an automatic ban. Its risk score is capped at 40.

### Password delay

Off by default. Password sign-in only.

The first attempt is immediate (`PasswordDelayAfterFailures` is 1). Later failures in a 15-minute window wait 1 second, then 3, then 5. The ceiling is 5 seconds and cannot be set above 30. Quick Connect, forgot-password, and playback are not delayed.

By default the delay runs only for a verified address, and it skips loopback, trusted, admin, and monitoring networks. A successful password sign-in clears the in-memory counter. The counter is gone after a process restart. If the client disconnects during the wait, the plugin does not continue into Jellyfin.

Active counters show on the Sign-in tab.

### Account cooldown

Off by default. This pause belongs to the plugin. It is not Jellyfin's permanent disable.

It starts only when one username is hit from at least 2 different addresses (the default asks for 5) and at least 2 failures (the default asks for 8) inside 15 minutes. One device, however many typos it makes, cannot start it. The pause lasts 15 minutes, does not get longer while it is active, and then ends. A successful password sign-in, or the clear button, ends it early.

Privileged networks can still sign in while it is active, unless that exception is turned off. Honeypot names are not cooled. The reply is 429 with `Retry-After`. The message does not say the Jellyfin account was disabled.

The pause is in memory. A process restart ends it.

### Honeypot name

The detector is on. The instant ban is off until an administrator turns it on and saves a name.

The name is useful only when it matches no Jellyfin user. If `GetUserByName` finds that name, or if the lookup throws, the instant ban stays idle. One use from a verified IPv4 address outside privileged networks creates a 60-minute automatic ban. The reason does not contain the name. Events show the subject as `(honeypot)`.

IPv6, unverified forwarded addresses, and admin, monitoring, and loopback networks are not banned by this switch. This switch does not require leaving Monitor only.

### Browser verification

Off by default. One provider at a time: none, Google reCAPTCHA v2, or Cloudflare Turnstile.

Both a site key and a secret are required. The secret field is left blank on later saves so the stored secret stays. It is not shown again.

When it is ready, the plugin adds a script to the HTML of `GET /`, `/web`, `/web/`, and `index.html` responses, before `</body>`, and only when the body is uncompressed HTML. Files in the `jellyfin-web` folder on disk are not edited. The response carries `X-Jelly-Security-Captcha`.

The script looks for the manual login form (`#txtManualPassword`, `.manualLoginForm`) and the forgot-password name field when the URL contains `forgotpassword`. The hint on the page is English: "Complete the check before continuing."

Google shows the "I'm not a robot" checkbox (`hl=ar`). Turnstile shows its checkbox (`language=ar`). The server checks the token with Google or Cloudflare. The hostname must match the request host. Tokens longer than 4096 characters are rejected. The token and the secret are not logged.

A missing or rejected token blocks that browser form. If the plugin cannot reach the provider, and fail-open is on (the default), the form is allowed. Fail-open does not allow a missing token.

Apps and TV clients are never asked. A browser is detected from names such as Jellyfin Web, Mozilla, Chrome, Safari, and Edg. Anything else, including curl, is unknown and skips the check by default. That is a known gap.

When **Block unrecognized clients too** is on, unknown clients must also supply a valid token. No widget is injected for them (they are not browsers), so the request is blocked until a valid token arrives, which a non-browser bot cannot obtain. This closes the path for bots that send no recognizable User-Agent at all. A bot that spoofs a TV app User-Agent is classified as an app and still bypasses — that needs a stricter client check. The option is off by default.

When **Require a real device ID for app classification** is on, the classifier parses the Jellyfin authorization header (`MediaBrowser Client="...", Device="...", DeviceId="...", Version="..."`). A client that claims to be a TV or mobile app — in User-Agent or in the Client field — but sends no `DeviceId` is downgraded to Unknown instead of App. Real Jellyfin apps always send a `DeviceId`; a bot that spoofs the User-Agent alone does not. Combined with *Block unrecognized clients too*, the spoofed app is then challenged like a browser. The option is off by default because some older or custom clients may not send a `DeviceId` and would be challenged along with the bots. `DeviceFingerprint.cs` does the parsing; `ClientKindClassifier.Classify` applies it.

Enabling this sends the token and the visitor address to the chosen provider. The domain must be registered there. Keys must be 20 to 200 characters from `A-Z`, `a-z`, `0-9`, `_`, and `-`.

### Lockout watch

Off by default. This reads two Jellyfin fields on each user and does not write them:

- `LoginAttemptsBeforeLockout`
- `InvalidLoginAttemptCount`

A limit of -1, 0, or empty means Jellyfin lockout is off for that account. Those accounts are counted. They are not listed as "almost locked."

There is no built-in lockout number. The plugin compares each account with that account's own limit. A limit of 25 is compared with 25. A limit of 6 is compared with 6.

The default warning is when 5 or fewer attempts remain, or when the counter has already reached the limit. Opening the page only reads. A security event is written on a failed password sign-in, at most once per account per 60 minutes.

The plugin does not write Jellyfin's failed-attempt counter. It also does not treat a rejected request as protection of that counter. Jellyfin updates the counter inside its own sign-in handler.

### Session watch

Off by default. Two things can raise an alert:

- A successful sign-in from an address this account has not used before. The first address is saved quietly and does not alert. Later new addresses do. Known addresses are stored in `known-addresses.json` (up to 32 per user).
- Four or more sessions at the same time for that user. The number is a setting. The smallest allowed value is 2.

Alerts are written on a successful password or Quick Connect sign-in, at most once per kind per account per 60 minutes. By default an unverified address is not treated as new, and loopback, trusted, admin, and monitoring networks do not raise the new-address alert. They are still remembered. The crowd alert still counts sessions.

Nothing is signed out by the alert. The button **Close other sessions** signs out that user's devices that are not playing. A session with something on screen, including a pause, is left alone. If a playing session has no device id, nothing is closed. The button does nothing while session watch is off.

The list on the page shows only accounts that are over the session limit or that have a session from an address not in the saved set.

### Edge channel and the paste snippet

Both are off by default.

The channel, when on, exposes:

- `GET /JellySecurity/edge/blocklist` — active ban targets as JSON
- `GET /JellySecurity/edge/deny.txt?format=nginx|caddy|cloudflare` — the same targets as text
- `POST /JellySecurity/edge/events` — record an address and a short note

The caller sends `X-Jelly-Security-Edge-Key`. The key must be at least 16 characters. Comparison is constant-time. By default the caller must be loopback or a known proxy. The route is marked anonymous in the plugin. Jellyfin can still apply its own authentication to the path.

The paste snippet is text on the Edge tab. The plugin does not write Nginx, Caddy, or Cloudflare files and does not reload them. The administrator copies the text.

The snippet limits sign-in POSTs only. Playback URLs are not in it. The default is 30 requests per minute per address, with an Nginx burst of 10, aimed at `127.0.0.1:8096`. A bad upstream (spaces, quotes, a full URL, a missing port) produces no snippet.

Caddy's snippet needs the separate module `github.com/mholt/caddy-ratelimit`. The plugin does not install it. Cloudflare's snippet is a rate-limiting rule expression for the Cloudflare dashboard. The plugin does not call the Cloudflare API and does not turn on a site-wide bot challenge.

The optional ban list inside the snippet is a snapshot. A shared key is written into the curl example only when the edge channel is on and the key is 16–200 characters from letters, digits, `_`, and `-`. Do not publish that snippet. The plugin does not run the curl.

This does not stop a flood that never reaches the proxy. It limits fast sign-in guesses at the proxy, after someone pastes the text. TV apps use the same sign-in paths, so a very small number can affect a household that shares one address.

## Attack timeline

The dashboard has an **Attack timeline** section. It groups failed and blocked sign-in events by source address into attack stories. Each story is one card:

- The subject (source address).
- Badges: failed count, blocked count, ban kind, highest risk band.
- Meta line: total attempts, distinct usernames tried, duration, first and last timestamp.
- Click the card to expand the chronological steps: each attempt, each detected pattern, and any ban applied, in order.

Only addresses with at least one failed or blocked attempt appear. Successful sign-ins from known addresses do not form stories. The timeline is read-only. It is built on demand from the events, incidents, and bans already stored — no extra files are written.

The endpoint is `GET /JellySecurity/timeline`. It returns up to 50 stories, each with up to 100 steps, sorted by most active first.

## API scan watch

Both options are off by default. This watches reconnaissance — a scanner probing enumeration endpoints before it ever reaches the sign-in form.

`ReconPathClassifier` decides which requests count. It is an allowlist of first-segment roots (`Users`, `Items`, `Library`, `System`, `Sessions`, `Shows`, `Plugins`, `api-docs`, `swagger`, and similar collection endpoints). A path counts only when its first segment is on the list and no later segment is a per-item endpoint. Per-item segments are excluded two ways: any GUID-shaped segment (real item, user, and session ids are GUIDs), and an exact-match set of deep endpoints (`Images`, `Stream`, `Download`, `Subtitles`, `PlaybackInfo`, `Playing`, `Progress`, and similar). Playback roots (`Videos`, `Audio`, `web`, `socket`) are not on the list at all. Depth is capped at four segments.

For each client address, `ReconWindow` keeps a sliding window of hits on those paths and counts three things: failed responses (4xx), unauthenticated requests (no token header or `api_key`), and distinct paths probed. The queue, counters, and path set all prune with the window and are capped, so memory stays bounded (the map holds at most 2000 addresses).

Two ways to cross the threshold, set by the dashboard fields:

- Enough failed (4xx) responses in the window. A scanner without a valid token collects 401s; a real client gets 2xx, so failures are the dominant signal.
- Heavy unauthenticated volume AND breadth — many unauthenticated requests across many distinct paths. Breadth separates enumeration from a client that retries one endpoint.

Crossing the threshold once per episode writes a Reconnaissance event, folds an `api_recon` signal into the incident system, pushes a live dashboard notification, and can fire the webhook. The episode flag resets only when the window fully expires, so a sustained scan does not spam incidents.

With **Slow down scanners** on, the crossing also starts a cooldown: the middleware answers enumeration endpoints with `429` plus `Retry-After` until it expires. Enforcement requires all of: a verified client address (socket address or a trusted forwarded header), no exception class (loopback, admin, monitoring, and trusted networks are never limited), and the watch and enforcement options both on. Sign-in and playback are never limited. A config change mid-cooldown still frees an address — the checks repeat on every request.

This is not a WAF and does not rate-limit all traffic. A patient scanner below the thresholds is not noticed. Legitimate clients browse `/Users` and `/Items` constantly — that is why only failures and unauthenticated breadth count, never successful volume.

## Detection, score, and alerts

Detectors only emit signals. The policy engine decides. No detector writes a ban by itself.

| Detector | Default | What it looks for |
|---|---|---|
| Single-IP brute force | On | Many failures from one address |
| Distributed account attack | On | Many addresses failing against one name. This alerts. It does not lock the account. |
| Password spray | On | Many names from one address |
| Username enumeration | On | Many distinct names |
| Credential-stuffing pattern | Part of the spray and speed signals | A pattern of automated trying. The plugin never sees the password, so it cannot know that a password was leaked. |
| Honeypot | On | The configured name was used |
| Administrative account targeting | On | A name listed in **Administrative usernames** |

The risk score is a local 0–100 number for the dashboard. It falls by half every 24 hours, in memory. Country data never increases it. It is not a calibrated industry score.

Similar signals fold into one incident. Alert cooldown is 15 minutes. A webhook is optional and off. A failed webhook does not stop sign-in. The URL is not shown again in a redacted backup.

Geography comes only from a local CSV if `LocalGeoFile` is set. Nothing is downloaded.

## Jellyfin lockout, in one paragraph

Jellyfin has its own per-user lockout. The plugin reads it when lockout watch is on. It never resets `InvalidLoginAttemptCount`, never changes `LoginAttemptsBeforeLockout`, and never sets the user disabled. A non-positive limit means that account is not locked by the counter. The plugin's cooldown is a separate, temporary pause and it expires by itself.

## Where data lives

Plugin files are under Jellyfin's plugin configuration folder, in `JellySecurity/`:

| File | Survives restart | Contents |
|---|---|---|
| `bans.json` | Yes | Manual and automatic bans |
| `events.json` | Yes | Security events. Default keep is 30 days or 20,000 events, whichever trims first. |
| `audit.json` | Yes | Policy changes, ban adds, cooldown and session actions. Capped around 2,000 rows. |
| `incidents.json` | Yes | Grouped alerts |
| `known-addresses.json` | Yes | Addresses already seen by session watch |

Password-delay counters and account cooldowns are in memory. A restart clears them. A cooldown also ends when its timer ends.

If one of the main store files is corrupt, the plugin logs the error, keeps the file, and stops saving so an empty file does not replace it. Fix the file and restart. A corrupt `known-addresses.json` is kept and not overwritten, without blocking the other files.

Backups can hide the webhook URL, honeypot name, captcha secret, and edge key. Restoring a redacted backup keeps the secrets already on the server. Restore does not force the honeypot instant ban off.

In-memory maps are capped (default 10,000 keys) so a flood of random names does not grow without a limit.

## HTTP API

Admin routes are under `/JellySecurity` and use Jellyfin's `RequiresElevation` policy. Hiding a button is not the check. The server rejects a caller who is not an administrator.

| Method | Path | What it returns or does |
|---|---|---|
| GET | `/JellySecurity/status` | Mode, health, counters, delay rows, cooldowns, honeypot state, lockout watch, session watch |
| GET | `/JellySecurity/snippet` | The edge paste text, or an empty text when the option is off |
| GET | `/JellySecurity/events` | Filtered events |
| GET | `/JellySecurity/events.csv` | The same events as CSV. Formula-like usernames are prefixed so a spreadsheet does not treat them as formulas. |
| GET | `/JellySecurity/incidents` | Grouped alerts |
| GET | `/JellySecurity/timeline` | Attack stories: events, patterns, and bans grouped by source address, in chronological order |
| GET | `/JellySecurity/stream` | Server-Sent Events stream — live notifications when events, bans, or incidents fire |
| GET | `/JellySecurity/audit` | Policy audit |
| GET | `/JellySecurity/bans` | Bans |
| POST | `/JellySecurity/bans` | Add a manual ban |
| DELETE | `/JellySecurity/bans?target=` | Remove a ban |
| GET | `/JellySecurity/report?hours=` | A report built from plugin events only |
| GET | `/JellySecurity/posture` | Findings about this plugin's settings |
| GET | `/JellySecurity/backup` | Settings and bans. Secrets can be redacted. |
| POST | `/JellySecurity/backup/preview` | What a restore would change |
| POST | `/JellySecurity/backup/restore` | Apply that file |
| POST | `/JellySecurity/cooldowns/clear` | End one username's plugin cooldown |
| POST | `/JellySecurity/sessions/close-others` | Sign out that user's devices that are not playing |

Edge routes are under `/JellySecurity/edge` and use the shared key, as described above.

Settings themselves are saved through Jellyfin's normal plugin configuration API, not through a custom save route.

## Source layout

```text
Jelly_Security.md                 this guide
README.md                         short English intro
README.ar.md                      short Arabic intro
CHANGELOG.md                      what each version added
build.yaml                        plugin catalog metadata
manifest.json                     Jellyfin repository manifest
Directory.Build.props             version 0.21.1.0 and compiler settings
Jellyfin.Plugin.JellySecurity.slnx
LICENSE
CONTRIBUTING.md
SECURITY.md
FEASIBILITY_REPORT.md             what the plugin relies on in Jellyfin
docs/architecture/                path maps and a short integration table
docs/compatibility/jellyfin-12.2.md
docs/operations/recovery.md
src/Jellyfin.Plugin.JellySecurity/
  Plugin.cs                       entry point and dashboard page
  PluginServiceRegistrator.cs     wires the engine and middleware
  Configuration/                  settings and the mode enum
  Integration/                    path classification and middleware
  Api/                            dashboard and edge controllers
  Web/configPage.html             the English dashboard page
  Storage/SecurityStore.cs        JSON files
  Core/Engine/                    decisions, posture, backup
  Core/Policies/                  bans, exceptions, schedule
  Core/Networking/                address parsing, proxy trust, IPv6 prefix
  Core/RateLimiting/              delay and cooldown
  Core/Detection/                 detectors, risk, lockout watch, events,
                                    client classification, device fingerprint,
                                    recon path classifier and window
  Core/Captcha/                   Google and Turnstile, policy
  Core/Edge/                      shared-key check and paste text
  Core/Sessions/                  new-address book and session rules
  Core/Geo/                       local CSV lookup and country block policy
  Core/Reports/                   the 24-hour style report and the attack timeline
tests/Unit/                       unit tests
```

`PluginServiceRegistrator` has a parameterless constructor, which Jellyfin requires. The project references `Jellyfin.Controller` and `Jellyfin.Model` 12.2.0 with runtime assets excluded, so the plugin uses the server's copies.

Warnings are errors. Nullable reference types are on.

## Tests and build

From the repository root:

```powershell
dotnet test Jellyfin.Plugin.JellySecurity.slnx -c Release
```

The DLL is written to:

`src/Jellyfin.Plugin.JellySecurity/bin/Release/net10.0/Jellyfin.Plugin.JellySecurity.dll`

The tests cover policies: addresses, bans, paths, captcha decisions, delay, cooldown, honeypot, lockout limits, the paste snippet, and session rules. They do not start a Jellyfin process.

## What this plugin does not do

- A request this plugin rejects does not write Jellyfin's failed-attempt counter, and it is not a substitute for that counter.
- The admin-route list is incomplete.
- Unknown clients skip browser verification.
- The edge route may still require a Jellyfin user session.
- There is no second factor. Building one inside the plugin would mean handling passwords or session tokens here, which this code does not do.
- The plugin does not edit the firewall, Nginx, Caddy, or a Cloudflare account.
- Country data does not raise the score, and threat lists are not downloaded.
- IPv6 prefixes are not banned automatically.
- The plugin does not disable Jellyfin users and does not reset their lockout counters.
- Playback is not cut automatically. The session button only signs out devices that are not playing.
- This is not a defense against a flood that never reaches Jellyfin or the proxy.
- The API scan watch does not see paths outside its allowlist, does not rate-limit traffic in general, and does not notice a scanner that stays below the thresholds.
- The local risk number is for display.

## Words used in the UI and the log

| Word | Meaning here |
|---|---|
| Monitor only | Automatic IP bans are off. |
| Verified | The client address came from the socket, or from a forwarded header the plugin is allowed to trust. |
| Blocked | The plugin refused the request. |
| Failed | Jellyfin refused the sign-in. |
| Succeeded | Jellyfin accepted it. |
| Not configured | That account's Jellyfin lockout limit is not a positive number. |
