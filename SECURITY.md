# Security policy

- Never log passwords, session tokens, or Quick Connect secrets.
- Default mode is Monitor Only. Automatic IP bans are off.
- If the client address cannot be verified, automatic IP enforcement stays off.
- Do not file issues that include production logs with real usernames and public IPs.
- Report a vulnerability privately to the repository owner before opening a public issue.

## Known limitations

These are documented honestly so users can make informed decisions. They are not bugs — they are boundaries of what the plugin can and cannot do.

### Client classification is header based

`ClientKindClassifier` reads the `User-Agent` and `Authorization` headers to decide whether a client is a browser, a TV/mobile app, or unknown. Both headers are client-controlled and can be spoofed.

- A bot that spoofs a TV app User-Agent is classified as `App` and bypasses the browser CAPTCHA. With `StrictDeviceFingerprint` on (v0.19.0.0), a client claiming to be an app must also send a `DeviceId` in the Jellyfin authorization header — without one, it is downgraded to `Unknown`. The option is off by default so that older or custom clients that send no `DeviceId` are not challenged along with the bots.
- A bot that sends no recognizable User-Agent is `Unknown`. With `CaptchaChallengeUnknown` on (v0.16.0.0), those clients are blocked. Without it, they bypass.
- A bot that spoofs a browser User-Agent is classified as `Web` and faces the CAPTCHA challenge. This is the correct behavior: if you claim to be a browser, you get the browser challenge.
- A sufficiently capable bot could still generate a `DeviceId` and spoof a full authorization header. Device fingerprinting raises the cost; it does not make spoofing impossible.

A stricter client verification mechanism (device attestation, signed client tokens) is outside the scope of this plugin. The plugin relies on Jellyfin's own authentication as the real identity check.

### Proxy trust and X-Forwarded-For

The plugin only trusts `X-Forwarded-For` when `TrustForwardedFor` is on and the socket address is in `KnownProxies`. The chain is walked right-to-left: known proxy hops are skipped, and the rightmost non-proxy address is the client. If any non-proxy hop remains to the left of the chosen client, the chain is marked ambiguous and automatic bans stay off.

This prevents the common attack of injecting a fake address at the left of the XFF chain when a proxy appends (rather than overwrites). It does not prevent a compromised proxy from lying. If your proxy is compromised, the plugin cannot help.

### Fail-open behavior

Two kinds of failure are distinguished:

- **Internal plugin failure** (an exception in the middleware): the request continues to Jellyfin. The plugin never replaces Jellyfin authentication.
- **Security verification failure** (missing or rejected CAPTCHA token): the request is blocked, even when `CaptchaFailOpen` is on.
- **Infrastructure failure** (CAPTCHA provider unreachable): `CaptchaFailOpen` (default on) allows the request. Turning it off blocks the request until the provider responds.

Fail-open never applies to a missing or rejected token. It applies only when the provider cannot be reached.

### CAPTCHA cookie bypass — not a vulnerability

A reviewer flagged `CaptchaChallenge.WasIncluded()` as a bypass risk. The method was dead code — never called from any execution path. `CaptchaPolicy.Evaluate()` blocks on a missing token regardless of any cookie state. The dead code has been removed (v0.16.0.0). Regression tests pin this behavior: a browser-classified client with no token is always blocked.

### IPv6 and prefix bans

By default, IPv6 addresses are never banned automatically. With `AutomaticIpv6PrefixBan` on (v0.16.0.0), the /64 prefix is banned instead. A /64 is the typical end-user allocation, so this contains address rotation inside one subnet. It does not contain a determined attacker who controls multiple /64s.

### API scan watch

The per-endpoint reconnaissance watch (v0.20.0.0) is deliberately narrow:

- It counts only an allowlist of enumeration endpoints (`/Users`, `/Items`, `/Library`, `/System/Info`, and similar collection routes). Playback, images, downloads, websockets, and per-item routes are never counted.
- The dominant signal is failed responses — a scanner without a token collects 401s, while a real client gets 2xx. This means a slow scanner that stays below the thresholds is not noticed, and a scanner that only probes paths outside the allowlist is invisible to it.
- Enforcement (429 cooldown) is opt-in and requires a verified client address plus no exception class. Admin, monitoring, and trusted networks can never be rate-limited, so an administrator cannot be cut off from the dashboard by this feature.
- It is not a general rate limiter or a WAF. Jellyfin's own auth endpoints, reverse proxy rules, and host-level tools remain the right place for blanket limits.

### What this plugin does not do

- It does not replace Jellyfin authentication.
- It does not provide 2FA.
- It does not modify `jellyfin.db` or Jellyfin's lockout counter.
- It does not disable Jellyfin users.
- It does not edit the firewall, Nginx, Caddy, or Cloudflare.
- It does not download threat lists or geo data.
- It does not see the password being tried.
