# Jelly Security — User Guide

This guide explains every tab, every field, and every button in the Jelly Security plugin for Jellyfin. It is written for the person who runs the server at home or for a small group — not for a security engineer. If a field confuses you, this is the place to look.

---

## Table of contents

1. [Before you start](#before-you-start)
2. [Dashboard tab](#dashboard-tab)
3. [Activity tab](#activity-tab)
4. [Sign-in tab](#sign-in-tab)
5. [Detection tab](#detection-tab)
6. [Addresses tab](#addresses-tab)
7. [Sessions tab](#sessions-tab)
8. [Edge tab](#edge-tab)
9. [More tab](#more-tab)
10. [Common problems and fixes](#common-problems-and-fixes)

---

## Before you start

### What this plugin does

Jelly Security watches sign-in attempts to your Jellyfin server. It can slow down, pause, or block someone who is guessing passwords. It does **not** check passwords itself — Jellyfin still does that. The plugin only decides what happens *around* the password check.

### What this plugin does not do

- It does **not** replace Jellyfin's login.
- It does **not** stop or delay playback (streaming, progress, scrubbing).
- It does **not** write to `jellyfin.db` or change your Jellyfin users.
- It does **not** edit your firewall, Nginx, Caddy, Cloudflare, or router.
- It does **not** collect or send your data anywhere (unless you turn on the webhook yourself).

### The most important rule

**Everything starts off.** When you install the plugin, it only watches. It does not block anyone. You turn on the features you want, one at a time, and press **Save**.

### The Save button

The **Save** button is at the bottom of every tab and sticks to the bottom of the screen. Any change you make — checking a box, typing a number — is not applied until you press Save. If you switch tabs without saving, your changes are lost.

---

## Dashboard tab

The Dashboard is the first thing you see. It tells you what is happening right now, without you needing to do anything.

### The banner

At the top, a colored banner tells you in plain words what the plugin did in the last 24 hours:

- **Green — "No threats detected"**: Your server is quiet. Nobody is trying to break in.
- **Green — "Your server is protected. Last 24h: 5 sign-in attempts stopped, 2 addresses blocked."**: The plugin caught and stopped attempts. Everything is under control.
- **Yellow — "Automatic blocks are waiting. The visitor address is not trusted yet."**: You turned on automatic blocks, but the plugin cannot tell who the real visitor is because you are behind a proxy and have not named it. See [Addresses tab — Proxy settings](#proxy-settings).
- **Yellow — "Watching only. Last 24h: 3 attempts stopped. Turn on automatic blocks to enforce them."**: The plugin noticed attempts but you are in Watch only mode, so it did not block anyone.

### The meters

Below the banner, ten colored boxes show counts for the last 24 hours. Click any box to see the records behind the number.

| Meter | What it means |
|---|---|
| **sign-in attempts, 24h** | Total sign-in tries (success + failure + blocked). |
| **rejected by Jellyfin** | Tries where Jellyfin said the password was wrong. |
| **stopped here** | Tries the plugin blocked before they reached Jellyfin. |
| **addresses blocked** | Addresses currently in the block list (manual + automatic). |
| **patterns noticed, 24h** | Attack patterns detected (brute force, spray, etc.). |
| **password waits active** | Addresses currently in a password delay right now. |
| **names paused** | Usernames currently paused by the cooldown feature. |
| **accounts near lockout** | Jellyfin accounts close to their own lockout limit. |
| **unfamiliar sessions** | Sessions from new addresses or too many at once. |
| **proxy snippet** | Shows which proxy target (Nginx/Caddy/Cloudflare) or "Off". |

**Colors**: green = quiet, yellow = activity, red = needs attention.

### Active enforcement

Below the meters, a section lists **everything the plugin is blocking right now** in one place:

- **Blocked address** — an IP the plugin is blocking, with the reason and when it expires. Click **Lift block** to remove it immediately.
- **Paused name** — a username the plugin paused, with how many addresses tried it and how long is left. Click **End pause** to let it sign in again.
- **Slowed address** — an IP inside the API scan slow-down (it gets `429` on enumeration endpoints). Click **End slow-down** to release it early.

This is the fastest way to release someone. You do not need to go to the Addresses tab or type the name manually.

### Live updates

The dashboard refreshes itself every 30 seconds and also updates **the moment something happens**: when a sign-in event is recorded, a ban is added or removed, or a pattern fires, the page reloads the affected lists immediately. If your network blocks the instant-update channel, the 30-second refresh still runs — nothing is lost.

### Last 24 hours

A short text report with totals: events, failed, succeeded, blocked, average risk. Click **Download report** to save it as a text file.

### How the settings fit together

A checklist that tells you if your settings make sense together. For example: "Automatic blocks are on, but no proxy is named. Bans will stay off until you name one." Read this after you change settings.

---

## Activity tab

The Activity tab keeps every saved record — the history the dashboard numbers are built from. Nothing on this tab blocks anyone; it only shows what already happened.

### Attack timeline

The **Attack timeline** tells each attack as a story: one card per source address, with the sequence of attempts, detected patterns, and any ban that was applied — in time order. Click a card to expand the steps. Reconnaissance events show as **Scan** steps; sign-in attempts show as **Attempt** steps; bans show as **Ban** steps.

### What happened

Four sections with raw records:

- **Jellyfin sign-in record**: sign-in and account events from Jellyfin's own log. Playback and library events are not included.
- **Notices**: warnings from the plugin that need your attention.
- **Patterns**: attack patterns the plugin detected, with the detector name, risk level, and recommended action.
- **Changes you made**: an audit log of every setting change you made.

### Sign-in list

A table of recent sign-in attempts. You can filter by result (All, Failed, Succeeded, Blocked, Unknown). Click **Refresh** to reload, or **Download CSV** to export the list as a spreadsheet file.

The list auto-refreshes every 30 seconds.

---

## Sign-in tab

This tab has the features that slow, pause, or challenge people trying to sign in. **All of them start off.** Turn on what you need, then Save.

### Slow repeated password guesses

**What it does**: After a few wrong passwords from the same address, the plugin makes the next try wait before it reaches Jellyfin. The first try is always immediate. Playback is never delayed.

**Why use it**: A script guessing passwords tries thousands per second. If each try has to wait 1, then 3, then 5 seconds, the script becomes useless.

**Fields**:

| Field | What to enter | Example |
|---|---|---|
| **Wait steps, in seconds** | A list of wait times, separated by commas. After the last step, that wait stays. | `1,3,5` |
| **Longest wait, in seconds (1–10)** | The maximum wait. Even after many failures, it never goes above this. | `10` |
| **Wrong passwords before the first wait** | How many wrong tries to allow before the delay starts. | `3` |
| **Count those failures over this many minutes** | Only count failures within this time window. Old failures are forgotten. | `15` |

**Two extra checkboxes**:

- **Only when the visitor address is trusted**: Only delay if the plugin can see the real visitor address (you named your proxy). Turn this on if you are behind a proxy.
- **Skip loopback, trusted, admin, and monitoring networks**: Do not delay requests from localhost, your trusted networks, admin networks, or monitoring tools. Turn this on so you do not lock yourself out.

**Waiting now**: Shows addresses currently in a delay, with their failure count and next wait time.

### Pause a name that is being sprayed

**What it does**: If the same username fails from several different addresses, the plugin pauses sign-in for that username for a set time. The Jellyfin account stays enabled — only sign-in is paused. One address failing many times is not enough; the point is to catch a distributed attack.

**Why use it**: A spray attack tries one password against many usernames from many addresses. This catches that pattern by name.

**Fields**:

| Field | What to enter | Example |
|---|---|---|
| **Pause for this many minutes** | How long the username is paused. | `30` |
| **Different addresses required (at least 2)** | How many distinct addresses must fail before the pause triggers. | `3` |
| **Failures required (at least 2)** | Total failures across those addresses. | `5` |
| **Look for that spray over this many minutes** | Only count failures within this time window. | `20` |

**Extra checkbox**:

- **Still allow loopback, trusted, admin, and monitoring networks during the pause**: So you can still sign in from your own network even if your username was paused.

**Paused now**: Shows usernames currently paused, with time left and how many addresses tried them.

**End the pause**: Type a username and click this to lift the pause immediately.

### Tell me before Jellyfin locks an account

**What it does**: Jellyfin has its own lockout feature (after N wrong tries, the account is locked). This plugin reads that counter and warns you *before* the lock happens. It does not change the counter.

**Why use it**: So you know an account is under attack before Jellyfin locks it and the real user cannot sign in.

**Fields**:

| Field | What to enter | Example |
|---|---|---|
| **Warn when this many tries, or fewer, remain** | Warn when the account has this many tries left before lockout. | `3` |
| **Wait this many minutes before warning again** | Do not repeat the same warning within this time. | `30` |

**Note**: A lockout limit of -1, 0, or empty means Jellyfin lockout is off for that account. The plugin shows that and does not warn.

### Ask the browser to confirm a person (CAPTCHA)

**What it does**: Adds a CAPTCHA check to the web sign-in form and the forgot-password form. TV apps are never asked (they cannot render the widget). Unknown clients — those with no recognizable User-Agent — are not asked by default. Jellyfin's files on disk are not modified.

**Why use it**: Stops automated scripts that do not run in a browser. A script that sends raw HTTP requests cannot solve a CAPTCHA.

**Fields**:

| Field | What to enter |
|---|---|
| **Check provider** | `Google reCAPTCHA`, `Cloudflare Turnstile`, or `None`. |
| **Allow sign-in when the provider cannot be reached** | If checked, sign-in continues if Google/Cloudflare is down. If unchecked, sign-in is blocked until the provider responds. |
| **Block unrecognized clients too** | If checked, clients with no recognizable User-Agent must also supply a valid token. This closes the path for bots that send no UA at all. Recognized TV apps stay exempt. Off by default. |
| **Require a real device ID for app classification** | If checked, a client that claims to be a Jellyfin app must send a `DeviceId` in its authorization header — which every real Jellyfin app does. A bot that spoofs a TV app User-Agent but sends no DeviceId is downgraded to Unknown, and is then challenged when "Block unrecognized clients too" is on. Older or custom clients that never send a DeviceId would also be challenged, so this is off by default. |
| **Site key** | The public key from your reCAPTCHA or Turnstile dashboard. |
| **Secret key** | The secret key from your dashboard. Leave blank to keep the saved one. It is never shown again after you save it. |

**How to set up Google reCAPTCHA**:

1. Go to <https://www.google.com/recaptcha/admin>.
2. Create a new site. Choose reCAPTCHA v2 ("I'm not a robot" checkbox).
3. Add your domain. **Important:** also add `localhost` so you can test on `127.0.0.1:8096`. If you do not add `localhost`, you will see the error `Localhost is not in the list of supported domains for this site key`. See [Common problems](#captcha-localhost-error).
4. Copy the **Site key** and **Secret key** into the plugin.
5. Save.

**How to set up Cloudflare Turnstile**:

1. Go to your Cloudflare dashboard > Turnstile.
2. Create a new widget. Choose "Managed" for the widget mode.
3. Add your domain. For local testing, add `localhost`.
4. Copy the **Site key** and **Secret key** into the plugin.
5. Save.

**The state line below the fields** tells you if the setup is ready:
- "Browser challenge is on, but a provider and a valid site key are still needed." → You need to pick a provider and enter a site key (at least 20 characters).
- "Google reCAPTCHA is ready." or "Cloudflare Turnstile is ready." → You are good to go.

### Treat one use of a decoy name as enough (Honeypot)

**What it does**: You pick a username that does not exist in Jellyfin. If anyone tries to sign in with that name, the plugin blocks their address immediately. A real username does nothing.

**Why use it**: Attackers who guess usernames will eventually try names that do not exist. A real user never types a fake name, so this is a very clean signal.

**Fields**:

| Field | What to enter | Example |
|---|---|---|
| **Decoy name** | A username that does not match any Jellyfin user. | `fakeadmin` |
| **Block that address for this many minutes** | How long to block the address. Only shows when the instant ban is on. | `60` |

**The state line** tells you if the name is safe:
- "That name belongs to a Jellyfin user, so the block stays off." → Pick a different name. The honeypot must not match a real user.
- "That name matches nobody. One use from a verified IPv4 address is blocked." → You are good to go.
- "A decoy name does not block anyone yet." → The instant ban is off. The detector still records uses of the name, but does not block.

**Note**: The detector uses the decoy name even without the instant ban. The ban is a separate switch.

---

## Detection tab

This tab holds the two watches that *notice* attacks: the pattern detectors and the API scan watch. They record what they see — they do not block anyone by themselves. To block, turn on the relevant feature in the Sign-in or Addresses tab.

### Patterns to notice

These are **detectors**. They record a signal in the Patterns section of the Activity tab. They do **not** block anyone by themselves. To block, turn on the relevant feature in the Sign-in tab or automatic blocks in the Addresses tab.

| Detector | What it records |
|---|---|
| **Many failures from one address** | One IP failing many times (brute force from one source). |
| **One name tried from many addresses** | One username tried from many IPs (distributed attack on one account). |
| **Many names from one address** | One IP trying many usernames (password spray). |
| **A search for usernames** | Behavior that looks like username enumeration. |
| **The decoy name was used** | Someone tried the honeypot name. |
| **A listed admin name was targeted** | Someone tried a username you listed in "Admin names to watch". |

**Admin names to watch**: A comma-separated list of usernames to watch. The word "admin" is not assumed — you must list the actual usernames.

### API scan watch

**What it does**: Watches the routes bots probe before they attack sign-in — enumeration endpoints such as `/Users`, `/Items`, `/Library`, `/System`, `/Sessions`, `api-docs`, and `swagger`. Playback routes, posters, downloads, subtitles, transcoding, static web files, websockets, and deep per-item routes are **never** watched, so library browsing is unaffected.

**How it decides**: The main signal is failed responses (`401`/`403`/`404`) — a client without a valid token collects them fast while a real client gets `2xx`. A second signal needs heavy **unauthenticated** volume spread across **many distinct paths**, which separates a scanner probing everything from a client retrying one endpoint. When a threshold is crossed the plugin records one `Reconnaissance` event and one pattern per episode — not one per request.

**Fields**:

| Field | What to enter |
|---|---|
| **Watch the API surface bots probe** | Turns the watch on. Events and patterns are recorded even with no enforcement. |
| **Slow down addresses that scan** | When the watch is on, a verified address that crosses a threshold gets `429 Too Many Requests` on enumeration endpoints for the slow-down minutes below. Requires a verified address — with a reverse proxy, name it in the Addresses tab first. Admin, monitoring, and trusted networks are never slowed. |
| **Failed requests that mark a scan** | How many 4xx responses inside the window mark the address. Default `30`. |
| **Unauthenticated requests that mark a scan** | Unauthenticated request count needed for the breadth rule. Default `120`. |
| **Distinct paths for the breadth rule** | How many different paths the unauthenticated volume must cover. Default `15`. |
| **Window minutes** | The sliding window all counters live in. Default `5`. |
| **Slow-down minutes** | How long the `429` slow-down lasts. Default `10`. It is temporary and never becomes a ban. |

**Note**: The slow-down only touches enumeration endpoints. Sign-in and playback are never rate-limited by this feature.

---

## Addresses tab

This tab is for blocking addresses manually, setting up automatic blocks, and configuring proxy trust.

### Block an address

**What it does**: Manually block a single IP address or a range from signing in.

**Fields**:

| Field | What to enter | Example |
|---|---|---|
| **Enforce the addresses I block** | Check this to actually block. If unchecked, the list is recorded but not enforced. | — |
| **Address or range** | A single IPv4/IPv6 address, or a CIDR range. Whole-internet ranges (`0.0.0.0/0`) are refused. | `203.0.113.5` or `10.0.0.0/24` |
| **Why** | A short reason. Shown in the block list. | "brute force" |
| **Minutes** | How long the block lasts. Leave empty for a permanent block. | `60` |

Click **Block this address** to add it. The list below shows all blocks. Active blocks have a **Remove** button (with a confirm dialog). Ended blocks are shown faded, without a Remove button.

### Block sign-in from countries I name

**What it does**: Blocks sign-in attempts whose address matches a country row you added. Each row is a name plus a list of address ranges.

**How to add a country**:

1. Click **Add a country**.
2. Type the country name in the name field (e.g. `US` or `Yemen`).
3. Either press **Fill** — this reads the ranges for that name from the local geo file you configured in the **More tab** — or paste a CIDR list yourself.
4. Check **On** to activate the row.
5. Click **Save** at the bottom.

**Fields**:

| Field | What to enter | Example |
|---|---|---|
| **Name** | A label for the row. Match the country text used in your geo file's second column when using Fill. | `CN`, `Russia`, `OM` |
| **Ranges** | CIDR blocks or single addresses, separated by commas or new lines. Every entry stays editable by hand. | `203.0.113.0/24, 198.51.100.0/24` |
| **On** | Whether this row blocks sign-in attempts. | — |
| **Fill** | Reads matching ranges from the local geo file (More tab). | — |
| **Remove** | Deletes the row. | — |

**Important**:

- A country row behaves like a manual block: **Enforce the addresses I block** must be checked, and admin/monitoring networks are never blocked.
- Rows without any ranges do nothing. Ranges with entries that do not parse are ignored.
- The plugin does not ship or download geo data. Fill only works when a local geo file is set in the **More tab**; otherwise paste ranges from a source you trust (e.g. a published country zone list).
- Country blocks are blunt: a VPN changes "country" instantly, and geo data goes stale over time. Most useful when your server is only meant for one country's traffic.

### Block an address after repeated failures

**What it does**: Automatically pause a verified address after it fails too many times.

**The mode dropdown**:

| Mode | Behavior |
|---|---|
| **Watch only** | Records everything, blocks nothing. The safest mode. |
| **Allow automatic blocks (Balanced)** | Blocks verified addresses after repeated failures. |
| **Allow automatic blocks (Strict)** | Same rule as Balanced today. Reserved for stricter rules in the future. |
| **Allow automatic blocks (Custom)** | Same rule as Balanced today. Reserved for custom tuning. |
| **Emergency** | Lifts the admin-network restriction. Use when you are locked out of your own server. |

**Fields**:

| Field | What to enter | Example |
|---|---|---|
| **Pause a verified address after repeated failures** | Check this to enable automatic blocks. Does nothing in Watch only mode. | — |
| **Failures before the pause** | How many failures before the address is paused. | `5` |
| **Count them over this many minutes** | Only count failures within this time window. | `15` |
| **Ban the /64 prefix for IPv6 addresses** | When off (default), IPv6 addresses are never banned automatically — fail-safe. When on, the whole /64 prefix (the typical end-user allocation) is paused instead of one address, so a client that rotates addresses inside its subnet is still contained. Broader than a single-address ban, so it stays off until you choose it. | — |

**Important**: An unverified address is never blocked automatically. If you are behind a proxy, you must name it (see below) or automatic blocks stay off.

**IPv6 note**: Without the /64 prefix option, IPv6 failures are still recorded and counted for detection (brute force, spray, distributed), but no automatic ban is stored. With the option on, the ban targets the /64 network, not the single address.

**Also apply sign-in blocks to Quick Connect**: When checked, all sign-in blocks (delays, pauses, bans, CAPTCHA) also apply to Quick Connect sign-in. When unchecked, Quick Connect is not affected. Quick Connect is another way to sign in — if you do not protect it, an attacker can bypass your sign-in blocks by using it.

### Proxy settings (collapsible)

Open this if Jellyfin is behind a reverse proxy (Nginx, Caddy, Cloudflare, etc.) or if some networks should be left alone.

| Field | What to enter | Example |
|---|---|---|
| **Use X-Forwarded-For from a proxy I name** | Check this if you are behind a proxy. The plugin reads the real visitor address from the `X-Forwarded-For` header, but only from proxies you name. | — |
| **Proxy addresses** | The IP addresses of your proxies, comma-separated. Automatic blocks stay off until at least one is named. | `203.0.113.10` |
| **Trusted networks** | Networks where manual blocks apply but automatic blocks do not. | `192.168.1.0/24` |
| **Admin networks** | Networks where neither manual nor automatic blocks apply. These are your own admin networks. | `192.168.1.0/24` |
| **Keep known admin changes inside admin networks** | When checked, admin write routes are only accepted from admin networks. Ignored when admin networks are empty. Note: this is a partial map and does not cover every admin API. | — |
| **Monitoring networks** | Networks that are record-only (never blocked). For monitoring tools like uptime checkers. | `10.0.0.5` |

---

## Sessions tab

This tab watches for unfamiliar sign-in activity and lets you manage sessions. **Playback is never stopped automatically.**

### Notice a sign-in that does not look like this account

**What it does**: When a user signs in from a new address, or has too many sessions at once, the plugin lists it. The first address a user signs in from is remembered quietly. Playback stays up until you act.

**Fields**:

| Field | What to enter | Example |
|---|---|---|
| **Warn at this many sessions at once** | Warn when a user has this many sessions at the same time. | `3` |
| **Wait this many minutes before warning again** | Do not repeat the same warning within this time. | `30` |
| **Ignore an address that is not trusted** | Only warn for verified addresses. | — |
| **Do not warn for loopback, trusted, admin, or monitoring networks** | Skip warnings for your own networks. | — |

**The session list** shows: username, device name, address, whether it is playing, the title, and why it was flagged.

**Sign out other devices for this name**: Type a username and click **Sign out devices that are not playing** to sign out all non-playing sessions for that user. A confirm dialog appears first. Playing sessions are left alone.

### Record session administration, not playback

**What it does**: When checked, the plugin records session list reads and sign-out actions in its audit log. Playback, progress, and play commands are never recorded. This does not sign anyone out by itself.

**Why use it**: So you have a record of who signed out devices and when, without recording what people watched.

---

## Edge tab

This tab builds text you can paste into your reverse proxy (Nginx, Caddy, or Cloudflare) so sign-in guessing is slowed before it reaches Jellyfin.

**This is an addition, not a replacement.** The snippet only adds rate-limiting to sign-in routes. It does not touch your domain, SSL certificates, playback proxy_pass, or any other existing configuration.

### Build a rate-limit snippet for my proxy

**What it does**: Produces text you paste into your proxy config. The plugin does not write the file — it only gives you the text.

**Fields**:

| Field | What to enter | Example |
|---|---|---|
| **Where you will paste it** | Nginx, Caddy, or Cloudflare. | `Nginx` |
| **Jellyfin host and port the proxy reaches** | The address your proxy uses to reach Jellyfin. Cloudflare does not use this. | `127.0.0.1:8096` |
| **Sign-in requests per address each minute** | How many sign-in tries per minute per address before the proxy blocks. | `30` |
| **Extra Nginx burst** | Nginx only. How many extra requests to allow in a short burst. 0 means no burst. | `10` |
| **Include the current block list in the text** | Adds your current bans to the snippet as comments. Only works if the edge channel is on and has a valid shared key. | — |

**How to use it**:

1. Check the box, pick your proxy, set the numbers.
2. Press **Save**.
3. Press **Refresh** to load the text.
4. Press **Copy** to copy it.
5. **Back up your proxy config first** (for example: `cp /etc/nginx/sites-available/jellyfin /etc/nginx/sites-available/jellyfin.bak`).
6. Paste the text where the snippet tells you (it says exactly where).
7. Test the config (`nginx -t` for Nginx, `caddy validate` for Caddy).
8. If it passes, reload (`systemctl reload nginx` or `systemctl reload caddy`).
9. If it fails, restore from your backup and try again.

**Cloudflare** does not need a reload — the rule applies immediately. To remove it, delete the rule in the Cloudflare dashboard.

### Let the proxy read the block list with a shared key

**What it does**: Exposes a limited endpoint at `/JellySecurity/edge/` that your proxy can read to stay in sync with the addresses this plugin has blocked. The proxy authenticates with a shared key.

**Fields**:

| Field | What to enter | Example |
|---|---|---|
| **Only from loopback or a named proxy** | When checked, the endpoint accepts requests only from `127.0.0.1`, `::1`, or addresses in Known Proxies (Addresses tab). When unchecked, any address with the correct key can read the list. | — |
| **Shared key** | At least 16 characters: letters, digits, underscores, or hyphens. Leave blank to keep the saved key. | `my-edge-key-2026-abc` |

**Why use it**: So your proxy can block the same addresses the plugin blocks, without you copying the list by hand.

---

## More tab

### Alerts

When the plugin detects a pattern (brute force, spray, enumeration, honeypot hit), it records an incident. The options here control how often it records the same incident and whether it also sends it to a webhook.

| Field | What to enter | Example |
|---|---|---|
| **Minutes before a similar alert is recorded again** | When the same detector fires for the same target, wait this many minutes before recording another incident. Prevents alert flooding. | `15` |
| **Send an alert to a webhook** | When checked, the plugin sends a JSON payload to the URL below when an incident is recorded. A failed delivery never blocks sign-in. | — |
| **Webhook URL** | `http` or `https`, public address only. Private, loopback, and link-local addresses are rejected. Hostnames are DNS-resolved and must resolve to public IPs. | `https://example.com/hook` |

**Webhook payload**: The plugin sends a JSON object with the incident details (detector, target, risk, time, recommended action). You can use this with Discord, Slack, n8n, or any service that accepts a webhook.

**SSRF protection**: The plugin resolves the hostname and checks every IP it resolves to. If any IP is private, loopback, or link-local, the webhook is rejected. This prevents the plugin from being used to scan your internal network.

### Local lookup

| Field | What to enter | Example |
|---|---|---|
| **Local geo file (CSV)** | A path to a local CSV file with country data for IP addresses. The file stays on disk. Country data does not raise a block by itself. | `/data/geo.csv` |

### Backup and restore

**Download a backup**: Click **Download backup (secrets redacted)** to download a JSON file with all your settings and bans. Secrets (webhook URL, honeypot name, captcha secret, edge key) are replaced with `(redacted)` so the file is safe to keep or share.

**Restore from a backup**:

1. Paste a backup JSON into the text box.
2. Click **Preview** to see what would change. The preview lists every difference and any warnings.
3. If you are happy with the preview, click **Apply**.
4. A confirm dialog appears. Click OK to replace your current settings and bans.
5. Secrets on the server (webhook, honeypot, captcha, edge key) are kept — the backup does not overwrite them.

**What the backup includes**: all plugin settings, all bans (manual and automatic), and the schema version. It does **not** include Jellyfin users, passwords, or any data from `jellyfin.db`.

---

## Common problems and fixes

### "I am locked out of my own server"

**Cause**: You blocked your own address, or the admin network restriction is too strict.

**Fix**:
1. If you can still reach the Dashboard, go to the **Active enforcement** section and click **Lift block** or **End pause**.
2. If you cannot reach the Dashboard at all, switch the mode to **Emergency** in the Addresses tab. This lifts the admin-network restriction.
3. If that does not work, stop Jellyfin, delete the plugin config file at `C:\ProgramData\Jellyfin\Server\plugins\configurations\Jellyfin.Plugin.JellySecurity.xml` (Windows) or the equivalent on your system, and restart. This resets all plugin settings to defaults (everything off).

### "Automatic blocks are not working"

**Cause**: You are behind a proxy but have not named it, or the visitor address is not verified.

**Fix**:
1. Go to **Addresses tab** > **Proxy settings** (collapsible).
2. Check **Use X-Forwarded-For from a proxy I name**.
3. Enter your proxy's IP address in **Proxy addresses**.
4. Save.
5. The banner should change from yellow to green.

### "The CAPTCHA does not appear on the login page"

**Cause**: The provider is set to `None`, or the site key is too short, or you have not saved.

**Fix**:
1. Go to **Sign-in tab** > **Ask the browser to confirm a person**.
2. Pick a provider (Google reCAPTCHA or Cloudflare Turnstile).
3. Enter a site key (at least 20 characters).
4. Enter the secret key.
5. Save.
6. The state line below the fields should say "Google reCAPTCHA is ready." or "Cloudflare Turnstile is ready."

### <a name="captcha-localhost-error"></a>"Localhost is not in the list of supported domains for this site key"

**Cause**: You are testing on `127.0.0.1:8096` or `localhost`, but you did not add `localhost` to the list of allowed domains when you created the reCAPTCHA site key.

**Fix**:
1. Go to <https://www.google.com/recaptcha/admin>.
2. Open your site.
3. Add `localhost` to the list of domains.
4. Save.
5. Wait a few minutes for the change to take effect.
6. Reload the Jellyfin login page.

**For Cloudflare Turnstile**: Go to your Cloudflare dashboard > Turnstile > your widget > Settings > add `localhost` to the hostname list.

**Note**: `localhost` and `127.0.0.1` are separate entries in Google's list. Add both to be safe.

### "The Edge snippet says 'No snippet yet'"

**Cause**: You changed the fields but did not save, or the snippet feature is off.

**Fix**:
1. Check **Build a rate-limit snippet for my proxy**.
2. Set the fields.
3. Press **Save**.
4. Press **Refresh** (next to Copy).
5. The text should appear in the box.

### "The Copy button does not copy"

**Cause**: Your browser blocked the clipboard because the connection is not HTTPS.

**Fix**: The plugin has a fallback that selects the text and uses the old copy method. If that also fails, the note will say "Select the text manually and press Ctrl+C." Click inside the text box, press Ctrl+A to select all, then Ctrl+C to copy.

### "The backup download does not start"

**Cause**: A popup blocker, or the plugin is not reachable.

**Fix**:
1. Make sure you see "Building backup…" when you click the button.
2. If it says "Could not build the backup," check that Jellyfin is running and the plugin is loaded (Dashboard tab should show numbers, not dashes).
3. Allow popups for your Jellyfin URL in your browser, or try a different browser.

### "I restored a backup but my webhook stopped working"

**Cause**: The backup had secrets redacted. When you restore, the plugin keeps the secrets that are already on the server. If the server had no webhook URL saved, the webhook stays empty.

**Fix**: Go to **More tab** > **Webhook URL** and enter the URL again. Save.

### "The banner says 'Automatic blocks are waiting. The visitor address is not trusted yet.'"

**Cause**: You turned on automatic blocks and "Use X-Forwarded-For," but you did not name any proxy.

**Fix**: Go to **Addresses tab** > **Proxy settings**. Enter your proxy's IP address in **Proxy addresses**. Save.

### "Playback stopped or stuttered after I turned something on"

**Cause**: This should not happen — the plugin never classifies, delays, or blocks playback routes. If it did, it is a bug.

**Fix**:
1. Switch the mode to **Watch only** in the Addresses tab. This disables all blocking.
2. Check the **Activity tab** > **Notices** for any warning.
3. Report the issue with the time, the address, and what you were doing.

### "The plugin page is blank or shows an error"

**Cause**: The plugin failed to load, or Jellyfin started with the wrong data directory.

**Fix**:
1. Check the Jellyfin log for "Loaded plugin: Jelly Security." If it is not there, the plugin is not installed correctly.
2. If you started Jellyfin manually, make sure you passed `--datadir` with the correct path. On Windows, the correct path is usually `C:\ProgramData\Jellyfin\Server`. Without this, Jellyfin uses an empty data directory and shows the setup wizard.
3. Restart Jellyfin with the correct command or use the tray app.
