using Jellyfin.Plugin.JellySecurity.Configuration;
using Jellyfin.Plugin.JellySecurity.Core.Captcha;
using Jellyfin.Plugin.JellySecurity.Core.Detection;
using Jellyfin.Plugin.JellySecurity.Core.Edge;
using Jellyfin.Plugin.JellySecurity.Core.Geo;
using Jellyfin.Plugin.JellySecurity.Core.Networking;
using Jellyfin.Plugin.JellySecurity.Core.Reports;
using Jellyfin.Plugin.JellySecurity.Core.Policies;
using Jellyfin.Plugin.JellySecurity.Core.RateLimiting;
using Jellyfin.Plugin.JellySecurity.Core.Sessions;
using Jellyfin.Plugin.JellySecurity.Integration;
using Jellyfin.Plugin.JellySecurity.Storage;
using Jellyfin.Data.Queries;
using MediaBrowser.Controller.Devices;
using MediaBrowser.Controller.Library;
using MediaBrowser.Controller.Session;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.JellySecurity.Core.Engine;

/// <summary>
/// Central decision point. Default operation is observation only.
/// </summary>
public sealed class SecurityEngine
{
    private readonly SecurityStore _store;
    private readonly ProxyTrustValidator _proxy;
    private readonly IUserManager _users;
    private readonly ISessionManager _sessions;
    private readonly IDeviceManager _devices;
    private readonly ILogger<SecurityEngine> _logger;
    private readonly SecurityEventHub? _hub;
    private readonly BoundedMap<AttemptWindow> _ipFailures = new(10000);
    private readonly BoundedMap<ReconWindow> _recon = new(2000);
    private readonly BoundedMap<TimedSet> _accountIps = new(10000);
    private readonly BoundedMap<TimedSet> _ipUsernames = new(10000);
    private readonly BoundedMap<StrikeState> _strikes = new(10000);
    private readonly WebhookPublisher _webhook = new();
    private readonly HistoricalRisk _history = new();
    private readonly PasswordDelayTracker _passwordDelay = new(10000);
    private readonly AccountCooldownTracker _accountCooldown = new(10000);
    private readonly Dictionary<string, DateTimeOffset> _lockoutNotices = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _lockoutGate = new();
    private readonly Dictionary<string, DateTimeOffset> _sessionNotices = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _sessionGate = new();
    private readonly KnownAddressBook _addresses = new();
    private bool _addressesDirty;
    private DateTimeOffset _lastAddressFlush = DateTimeOffset.UtcNow;
    private readonly object _addressFlushGate = new();
    private IReadOnlyList<Geo.GeoRecord> _geo = [];
    private string _geoPath = string.Empty;
    private int _geoLookups;
    private int _geoHits;

    public SecurityEngine(SecurityStore store, ProxyTrustValidator proxy, IUserManager users, ISessionManager sessions, IDeviceManager devices, ILogger<SecurityEngine> logger, SecurityEventHub? hub = null)
    {
        _store = store;
        _proxy = proxy;
        _users = users;
        _sessions = sessions;
        _devices = devices;
        _logger = logger;
        _hub = hub;
        _addresses.Import(store.ReadKnownAddresses());
    }

    public PluginConfiguration Config => Plugin.Instance?.Configuration ?? new PluginConfiguration();

    /// <summary>
    /// Publishes a live notification to connected SSE clients. No-op when no
    /// hub is registered (e.g. in unit tests). Never throws — a failed push
    /// must not break sign-in processing.
    /// </summary>
    private void Notify(LiveNotification notification)
    {
        try { _hub?.Publish(notification); }
        catch { /* notifications are best-effort */ }
    }

    /// <summary>
    /// Exposes the hub for the SSE controller to subscribe to.
    /// </summary>
    public SecurityEventHub? Hub => _hub;

    public ClientIdentity Resolve(Microsoft.AspNetCore.Http.HttpContext context)
    {
        return _proxy.Resolve(context, Config);
    }

    public EnvironmentStatus Health()
    {
        return EnablementGate.Evaluate(Config);
    }

    public IReadOnlyList<PostureFinding> Posture()
    {
        return PostureAuditor.Audit(Config, _store.Bans);
    }

    public bool AppliesSignInBan(Integration.AuthPathKind kind)
    {
        var config = Config;
        return kind switch
        {
            Integration.AuthPathKind.QuickConnect => config.ProtectQuickConnect,
            Integration.AuthPathKind.Password or Integration.AuthPathKind.PasswordReset => true,
            _ => false
        };
    }

    public BanDecision EvaluateAdminAccess(ClientIdentity identity)
    {
        return AdminRestriction.Evaluate(Config, identity);
    }

    public SecurityBackupDocument CreateBackup(bool includeSecrets)
    {
        return ConfigBackup.Export(Config, _store.Bans, includeSecrets);
    }

    public ImportPreview PreviewBackup(string json)
    {
        return ConfigBackup.Preview(json, Config);
    }

    public OperationResult<int> ApplyBackup(string json)
    {
        var preview = ConfigBackup.Preview(json, Config);
        if (!preview.Ok || preview.Document is null)
        {
            return OperationResult<int>.Fail(preview.Message);
        }

        var incoming = preview.Document.Configuration;
        if (preview.Document.SecretsRedacted)
        {
            incoming.WebhookUrl = Config.WebhookUrl;
            incoming.HoneypotUsername = Config.HoneypotUsername;

            incoming.CaptchaSecret = Config.CaptchaSecret;
            incoming.EdgeSharedKey = Config.EdgeSharedKey;
        }

        incoming.SchemaVersion = PluginConfiguration.CurrentSchemaVersion;
        Plugin.Instance?.UpdateConfiguration(incoming);
        _store.ReplaceBans(preview.Document.Bans);
        _store.AddAudit("BackupRestored", "configuration", string.Join("; ", preview.Changes));
        return OperationResult<int>.Success(preview.Document.Bans.Count, preview.Message);
    }

    public BanDecision EvaluatePreAuth(ClientIdentity identity, string path)
    {
        var config = Config;
        var now = DateTimeOffset.UtcNow;
        if (identity.Address is null)
        {
            return BanDecision.Allow("No client address.");
        }

        var exception = ExceptionPolicy.Classify(identity.Address, config);
        var ban = _store.FindActiveBan(identity.Address, now);
        if (ban is null)
        {
            var geoName = GeoBlockPolicy.Match(config, identity.Address);
            if (geoName is not null)
            {
                ban = new BanRecord
                {
                    Target = identity.Address,
                    Kind = BanKind.Geo,
                    Reason = "Country block list: " + geoName,
                    CreatedBy = "country block"
                };
            }
        }

        if (ban is null)
        {
            return BanDecision.Allow("No active ban.");
        }

        var enforceManual = config.ApplyManualBans
            && ban.Kind is BanKind.Manual or BanKind.Cidr or BanKind.Geo
            && ExceptionPolicy.AllowsManualBan(exception);
        var enforceAutomatic = _proxy.AllowsAutomaticIpBans(config, identity)
            && ban.Kind is BanKind.AutomaticTemporary or BanKind.Progressive or BanKind.AutomaticPrefix
            && ExceptionPolicy.AllowsAutomaticBan(exception);

        if (enforceManual || enforceAutomatic)
        {
            return BanDecision.Deny(ban, $"Active ban matches this address ({exception}).");
        }

        if (exception is ExceptionClass.Administrative or ExceptionClass.Monitoring)
        {
            return BanDecision.Allow($"Exception {exception} outranks this ban.");
        }

        return BanDecision.Allow("A matching ban exists but enforcement is off (Monitor Only or automatic IP bans disabled).");
    }

    /// <summary>
    /// Addresses currently inside an active recon rate-limit, with the seconds
    /// left. Shown in the dashboard status so an admin can see and lift them.
    /// </summary>
    public IReadOnlyList<ReconLimitedRow> ReconLimitedRows()
    {
        var now = DateTimeOffset.UtcNow;
        var rows = new List<ReconLimitedRow>();
        foreach (var pair in _recon.Snapshot())
        {
            if (pair.Value.IsLimited(now))
            {
                var left = pair.Value.LimitedUntilUtc ?? now;
                rows.Add(new ReconLimitedRow(pair.Key, Math.Max(1, (int)Math.Ceiling((left - now).TotalSeconds))));
            }
        }

        return rows;
    }

    /// <summary>Ends the recon rate-limit for one address. Returns false when no limit was active.</summary>
    public bool ClearReconLimit(string? address)
    {
        var ip = IpNormalizer.Normalize(address);
        if (ip is null || !_recon.TryGetValue(ip, out var window) || !window.ClearLimit(DateTimeOffset.UtcNow))
        {
            return false;
        }

        _store.AddAudit("ReconLimitCleared", ip, "Administrator ended the API scan slow-down.");
        Notify(new LiveNotification { Type = "ban", Summary = $"API scan slow-down ended for {ip}" });
        return true;
    }

    /// <summary>
    /// Cheap pre-request check on API-surface paths. Returns Block only when the
    /// address is inside an active recon cooldown. The limit is only ever set
    /// for a verified, non-exception address, but the checks repeat here so a
    /// config change mid-cooldown still frees privileged networks.
    /// </summary>
    public ReconLimitDecision EvaluateReconLimit(ClientIdentity identity)
    {
        var config = Config;
        if (identity.Address is null
            || !_recon.TryGetValue(identity.Address, out var window))
        {
            return ReconLimitDecision.Allow;
        }

        return ReconPolicy.ShouldBlock(config, identity, window, DateTimeOffset.UtcNow, out var seconds)
            ? new ReconLimitDecision(true, seconds)
            : ReconLimitDecision.Allow;
    }

    /// <summary>
    /// Records one request against the API recon surface. When the address
    /// crosses the failure or breadth threshold for the first time in an
    /// episode, a Reconnaissance event and an incident are recorded, a live
    /// notification is pushed, and — with ReconEnforce on, a verified address,
    /// and no exception class — a 429 cooldown starts on enumeration endpoints.
    /// </summary>
    public void ObserveApiRequest(ClientIdentity identity, string path, bool hasToken, int statusCode)
    {
        var config = Config;
        if (!config.ReconWatchEnabled || identity.Address is null)
        {
            return;
        }

        var now = DateTimeOffset.UtcNow;
        var windowSpan = TimeSpan.FromMinutes(Math.Max(1, config.ReconWindowMinutes));
        var window = _recon.GetOrAdd(identity.Address, _ => new ReconWindow());
        var assessment = window.Record(path, hasToken, statusCode, now, windowSpan);

        var crossed = ReconPolicy.ThresholdCrossed(assessment, config);
        if (!crossed || !window.TakeReportFlag())
        {
            return;
        }

        var exception = ExceptionPolicy.Classify(identity.Address, config);
        var enforced = false;
        var limitMessage = string.Empty;
        if (ReconPolicy.MayEnforce(config, identity))
        {
            var until = now.AddMinutes(Math.Max(1, config.ReconCooldownMinutes));
            window.LimitUntil(until);
            enforced = true;
            limitMessage = $" Rate-limited on API enumeration endpoints until {until:HH:mm} UTC.";
        }

        var reason = exception is ExceptionClass.Administrative or ExceptionClass.Monitoring or ExceptionClass.Trusted
            ? $" {exception} network; no rate limit applied."
            : !config.ReconEnforce
                ? " Watch only; enforcement is off."
                : identity.Trust != SourceTrust.Verified
                    ? " Address trust is not verified; no rate limit applied."
                    : string.Empty;

        var message = $"API scan: {assessment.Failed} failed and {assessment.Unauth} unauthenticated requests across {assessment.DistinctPaths} paths in {config.ReconWindowMinutes}m.{reason}{limitMessage}";

        var signal = new DetectorSignal(
            "api_recon",
            "1",
            "address",
            identity.Address,
            assessment.Failed + assessment.Unauth,
            config.ReconWindowMinutes + "m",
            identity.Trust == SourceTrust.Verified ? "High" : "Low",
            "Moderate",
            "api_recon_scan",
            message);
        var risk = new RiskAssessment(
            identity.Trust == SourceTrust.Verified ? "Moderate" : "Low",
            identity.Trust == SourceTrust.Verified ? "High" : "Low",
            "Alert",
            "Observe or alert. No automatic account action.",
            ["api_recon"],
            message);
        var incident = _store.RecordIncident(signal, risk, config, now);
        if (incident is not null && incident.Count == 1)
        {
            _webhook.TryPublish(incident, config, _logger);
        }

        _store.AddEvent(
            new SecurityEvent
            {
                Kind = "Reconnaissance",
                Outcome = enforced ? "Blocked" : "Failed",
                Address = identity.Address,
                Path = path,
                Trust = identity.Trust.ToString(),
                Message = message,
                Enforced = enforced,
                RiskBand = risk.RiskBand,
                RecommendedAction = risk.RecommendedAction,
                RiskScore = 0,
                Country = LookupCountry(identity.Address)
            },
            config);

        Notify(new LiveNotification
        {
            Type = "incident",
            Summary = $"API scan from {identity.Address}: {assessment.Failed} failures across {assessment.DistinctPaths} paths"
        });
    }

    public void Observe(ClientIdentity identity, string path, string? username, int statusCode, bool enforced, string? blockReason = null)
    {
        var config = Config;
        var now = DateTimeOffset.UtcNow;
        var safeName = TextSanitizer.Display(username);
        var outcome = enforced && statusCode is 403 or 429
            ? "Blocked"
            : statusCode switch
            {
                429 => "Blocked",
                >= 200 and < 300 => "Succeeded",
                401 or 403 => "Failed",
                _ => "Unknown"
            };

        // Only credential-carrying paths feed the failure counter that drives
        // automatic bans. A 403 on an observed admin or session route is a
        // plain authorization denial, not a failed sign-in — counting it
        // could ban a legitimate client that polls a route it cannot use.
        if (identity.Address is not null && outcome == "Failed" && AuthPathClassifier.IsCredentialPath(path))
        {
            RegisterFailure(identity, safeName, config, now);
        }
        else if (identity.Address is not null && outcome == "Succeeded")
        {
            if (_ipFailures.TryGetValue(identity.Address, out var window))
            {
                window.Clear();
            }
        }

        NotePasswordDelay(identity, path, outcome, config, now);
        NoteAccountCooldown(identity, path, safeName, outcome, config, now);
        NoteLockoutWatch(username, path, outcome, config, now);
        NoteSessionWatch(identity, path, username, outcome, config, now);

        var exception = ExceptionPolicy.Classify(identity.Address, config);
        var failures = identity.Address is not null && _ipFailures.TryGetValue(identity.Address, out var failWindow)
            ? failWindow.Count(now)
            : 0;
        var distinctIps = !string.IsNullOrWhiteSpace(safeName) && _accountIps.TryGetValue(safeName, out var ips)
            ? ips.Count(now, TimeSpan.FromSeconds(Math.Max(15, config.DistributedWindowSeconds)))
            : 0;
        var distinctNames = identity.Address is not null && _ipUsernames.TryGetValue(identity.Address, out var names)
            ? names.Count(now, TimeSpan.FromMinutes(Math.Max(1, config.PasswordSprayWindowMinutes)))
            : 0;

        var displayName = ThreatDetectors.IsHoneypot(safeName, config) ? null : safeName;
        var context = new ObservationContext(identity, displayName, outcome, path, failures, distinctIps, distinctNames, exception, now);
        var signals = ThreatDetectors.Evaluate(
            context with { Username = safeName },
            config);
        var assessment = RiskEvaluator.Evaluate(signals, identity.Trust, exception);
        if (signals.Count > 0)
        {
            var incident = _store.RecordIncident(signals[0], assessment, config, now);
            if (incident is not null && incident.Count == 1)
            {
                _webhook.TryPublish(incident, config, _logger);
            }
        }

        // Build the message shown in the Reason column. The block reason comes
        // from the middleware and explains why the plugin stopped this request.
        // Without it, the column would show the risk assessment explanation
        // ("No threat detector fired.") which is meaningless to an admin.
        string message;
        if (outcome == "Blocked" && !string.IsNullOrWhiteSpace(blockReason))
        {
            message = blockReason!;
        }
        else if (outcome == "Blocked")
        {
            message = "Blocked by the plugin.";
        }
        else if (outcome == "Failed")
        {
            message = string.IsNullOrWhiteSpace(assessment.Explanation) || assessment.Explanation == "No threat detector fired."
                ? "Jellyfin rejected this sign-in attempt."
                : "Jellyfin rejected this sign-in attempt. " + assessment.Explanation;
        }
        else if (outcome == "Succeeded")
        {
            message = string.IsNullOrWhiteSpace(assessment.Explanation) || assessment.Explanation == "No threat detector fired."
                ? "Sign-in accepted by Jellyfin."
                : "Sign-in accepted by Jellyfin. " + assessment.Explanation;
        }
        else
        {
            message = string.IsNullOrWhiteSpace(assessment.Explanation)
                ? "Unrecognized response from Jellyfin."
                : assessment.Explanation;
        }

        _store.AddEvent(
            new SecurityEvent
            {
                Kind = "LoginAttempt",
                Outcome = outcome,
                Username = displayName,
                Address = identity.Address,
                Path = path,
                Trust = identity.Trust.ToString(),
                Message = message,
                Enforced = enforced,
                RiskBand = assessment.RiskBand,
                RecommendedAction = assessment.RecommendedAction,
                RiskScore = Score(identity, assessment, now),
                Country = LookupCountry(identity.Address)
            },
            config);

        Notify(new LiveNotification
        {
            Type = "event",
            Summary = $"{outcome} sign-in for {displayName ?? "unknown"} from {identity.Address ?? "unknown"}"
        });
    }

    public CaptchaDecision EvaluateCaptcha(Integration.AuthPathKind kind, string? userAgent, string? authorization, CaptchaCheck check)
    {
        var client = ClientKindClassifier.Classify(userAgent, authorization, Config.StrictDeviceFingerprint);
        return CaptchaPolicy.Evaluate(Config, kind, client, check);
    }

    public LoginDelayDecision PlanPasswordDelay(Integration.AuthPathKind kind, ClientIdentity identity)
    {
        var config = Config;
        var exception = ExceptionPolicy.Classify(identity.Address, config);
        if (!LoginDelayPolicy.Applies(config, kind, identity, exception) || identity.Address is null)
        {
            return LoginDelayDecision.Off("Password delay does not apply to this sign-in.");
        }

        var prior = _passwordDelay.Count(identity.Address, LoginDelayPolicy.Window(config), DateTimeOffset.UtcNow);
        return LoginDelayPolicy.Evaluate(config, prior);
    }

    public IReadOnlyList<PasswordDelayCounter> PasswordDelaySnapshot()
    {
        var config = Config;
        if (!config.PasswordDelayEnabled)
        {
            return [];
        }

        var now = DateTimeOffset.UtcNow;
        return _passwordDelay.Active(now)
            .Select(row =>
            {
                var decision = LoginDelayPolicy.Evaluate(config, row.Failures);
                return new PasswordDelayCounter(row.Address, row.Failures, (int)decision.Delay.TotalSeconds);
            })
            .ToArray();
    }

    private void NotePasswordDelay(ClientIdentity identity, string path, string outcome, PluginConfiguration config, DateTimeOffset now)
    {
        if (identity.Address is null || !AuthPathClassifier.IsPasswordSignInPath(path))
        {
            return;
        }

        var exception = ExceptionPolicy.Classify(identity.Address, config);
        if (!LoginDelayPolicy.Applies(config, AuthPathKind.Password, identity, exception))
        {
            return;
        }

        if (outcome == "Succeeded")
        {
            _passwordDelay.Clear(identity.Address);
            return;
        }

        if (outcome == "Failed")
        {
            _passwordDelay.RecordFailure(identity.Address, LoginDelayPolicy.Window(config), now);
        }
    }

    public AccountCooldownDecision PlanAccountCooldown(AuthPathKind kind, ClientIdentity identity, string? username)
    {
        var config = Config;
        var name = AccountCooldownPolicy.NormalizeUsername(username);
        if (name is null)
        {
            return AccountCooldownDecision.Allow("No username to pause.");
        }

        var now = DateTimeOffset.UtcNow;
        var active = _accountCooldown.Active(name, now);
        var exception = ExceptionPolicy.Classify(identity.Address, config);
        if (!AccountCooldownPolicy.Blocks(config, kind, identity, exception, active is not null))
        {
            return AccountCooldownDecision.Allow("Account cooldown does not apply.");
        }

        var remaining = Math.Max(1, (int)Math.Ceiling((active!.UntilUtc - now).TotalSeconds));
        return new AccountCooldownDecision(true, remaining, "Plugin cooldown is active for this username.");
    }

    public IReadOnlyList<AccountCooldownView> AccountCooldownSnapshot()
    {
        if (!Config.AccountCooldownEnabled)
        {
            return [];
        }

        var now = DateTimeOffset.UtcNow;
        return _accountCooldown.Snapshot(now)
            .Select(item => new AccountCooldownView(
                item.Username,
                item.UntilUtc,
                Math.Max(1, (int)Math.Ceiling((item.UntilUtc - now).TotalSeconds)),
                item.DistinctIps,
                item.Reason))
            .ToArray();
    }

    public bool ClearAccountCooldown(string? username)
    {
        var name = AccountCooldownPolicy.NormalizeUsername(username);
        if (name is null)
        {
            return false;
        }

        var removed = _accountCooldown.Clear(name);
        if (removed)
        {
            _store.AddAudit("AccountCooldownCleared", name, "Administrator ended the plugin cooldown.");
        }

        return removed;
    }

    private void NoteAccountCooldown(ClientIdentity identity, string path, string? username, string outcome, PluginConfiguration config, DateTimeOffset now)
    {
        var name = AccountCooldownPolicy.NormalizeUsername(username);
        if (!config.AccountCooldownEnabled || name is null || identity.Address is null || !AuthPathClassifier.IsPasswordSignInPath(path))
        {
            return;
        }

        if (ThreatDetectors.IsHoneypot(name, config))
        {
            return;
        }

        if (outcome == "Succeeded")
        {
            _accountCooldown.Clear(name);
            return;
        }

        if (outcome != "Failed" || _accountCooldown.Active(name, now) is not null)
        {
            return;
        }

        var window = AccountCooldownPolicy.Window(config);
        var levels = _accountCooldown.RecordFailure(name, identity.Address, window, now);
        if (!AccountCooldownPolicy.IsClearSpray(config, levels.DistinctIps, levels.Failures))
        {
            return;
        }

        var until = now.Add(AccountCooldownPolicy.Duration(config));
        if (_accountCooldown.TryBegin(name, now, until, levels.DistinctIps, "Distributed password attempts against this username."))
        {
            _store.AddAudit("AccountCooldownStarted", name, $"Until {until:u}. Jellyfin account was not disabled.");
        }
    }

    public LockoutWatchReport LockoutWatchSnapshot()
    {
        if (!Config.LockoutWatchEnabled)
        {
            return new LockoutWatchReport([], 0, 0, false);
        }

        try
        {
            var warn = Config.LockoutWatchRemaining;
            var rows = new List<LockoutWatchRow>();
            var without = 0;
            var read = 0;
            foreach (var user in _users.GetUsers())
            {
                read++;
                var attempts = user.InvalidLoginAttemptCount;
                var limit = user.LoginAttemptsBeforeLockout;
                var state = LockoutWatchPolicy.Classify(attempts, limit, warn);
                if (state == LockoutWatchPolicy.NotConfigured)
                {
                    without++;
                    continue;
                }

                if (state is not (LockoutWatchPolicy.Approaching or LockoutWatchPolicy.Reached))
                {
                    continue;
                }

                rows.Add(new LockoutWatchRow(
                    TextSanitizer.Display(user.Username, 80) ?? "unknown",
                    attempts,
                    limit ?? 0,
                    LockoutWatchPolicy.Remaining(attempts, limit),
                    state));
            }

            return new LockoutWatchReport(rows, without, read, false);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Lockout watch could not read account counters.");
            return new LockoutWatchReport([], 0, 0, true);
        }
    }

    private void NoteLockoutWatch(string? username, string path, string outcome, PluginConfiguration config, DateTimeOffset now)
    {
        if (!config.LockoutWatchEnabled || outcome != "Failed" || !AuthPathClassifier.IsPasswordSignInPath(path))
        {
            return;
        }

        var name = username?.Trim();
        if (string.IsNullOrEmpty(name))
        {
            return;
        }

        try
        {
            var user = _users.GetUserByName(name);
            if (user is null)
            {
                return;
            }

            var attempts = user.InvalidLoginAttemptCount;
            var limit = user.LoginAttemptsBeforeLockout;
            var state = LockoutWatchPolicy.Classify(attempts, limit, config.LockoutWatchRemaining);
            if (state is not (LockoutWatchPolicy.Approaching or LockoutWatchPolicy.Reached))
            {
                return;
            }

            var cooldown = TimeSpan.FromMinutes(LockoutWatchPolicy.CooldownMinutes(config.LockoutWatchCooldownMinutes));
            lock (_lockoutGate)
            {
                if (_lockoutNotices.TryGetValue(name, out var last) && now - last < cooldown)
                {
                    return;
                }

                _lockoutNotices[name] = now;
                if (_lockoutNotices.Count > 2000)
                {
                    foreach (var key in _lockoutNotices.Where(pair => now - pair.Value >= cooldown).Select(pair => pair.Key).ToArray())
                    {
                        _lockoutNotices.Remove(key);
                    }
                }
            }

            var remaining = LockoutWatchPolicy.Remaining(attempts, limit);
            _store.AddEvent(
                new SecurityEvent
                {
                    Kind = "LockoutWatch",
                    Outcome = "Unknown",
                    Username = TextSanitizer.Display(user.Username, 80) ?? name,
                    Path = path,
                    Message = $"Read {attempts} of {limit ?? 0} failed attempts on this account's own Jellyfin limit ({remaining} remaining). The plugin did not change the counter.",
                    Enforced = false
                },
                config);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Lockout watch could not read the account counter.");
        }
    }

    public SessionWatchReport SessionWatchSnapshot()
    {
        if (!Config.SessionWatchEnabled)
        {
            return new SessionWatchReport([], 0, 0);
        }

        try
        {
            var grouped = ReadSessions()
                .GroupBy(row => row.Username, StringComparer.OrdinalIgnoreCase)
                .ToArray();
            var rows = new List<SessionWatchRow>();
            var over = 0;
            var fresh = 0;
            foreach (var group in grouped)
            {
                var many = SessionWatchPolicy.TooMany(group.Count(), Config.SessionWatchConcurrent);
                var hasNew = group.Any(row => IsUnseen(group.Key, row.Address));
                if (!many && !hasNew)
                {
                    continue;
                }

                if (many)
                {
                    over++;
                }

                if (hasNew)
                {
                    fresh++;
                }

                var reason = many && hasNew
                    ? SessionWatchPolicy.Both
                    : many ? SessionWatchPolicy.ManySessions : SessionWatchPolicy.NewAddress;
                rows.AddRange(group.Select(row => row with { Reason = reason }));
            }

            return new SessionWatchReport(rows, over, fresh);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Session watch could not read sessions.");
            return new SessionWatchReport([], 0, 0);
        }
    }

    public async Task<SessionCloseResult> CloseOtherSessionsAsync(string? username)
    {
        if (!Config.SessionWatchEnabled)
        {
            return new SessionCloseResult(false, 0, 0, "Session watch is off.");
        }

        var name = username?.Trim();
        if (string.IsNullOrEmpty(name))
        {
            return new SessionCloseResult(false, 0, 0, "Username is required.");
        }

        try
        {
            var user = _users.GetUserByName(name);
            if (user is null)
            {
                return new SessionCloseResult(false, 0, 0, "No Jellyfin user with that name.");
            }

            var sessions = _sessions.Sessions
                .Where(session => session.UserId == user.Id || string.Equals(session.UserName, user.Username, StringComparison.OrdinalIgnoreCase))
                .ToArray();
            var playingIds = sessions
                .Where(session => session.NowPlayingItem is not null)
                .Select(session => session.DeviceId)
                .ToArray();
            var devices = _devices.GetDevices(new DeviceQuery { UserId = user.Id }).Items;
            var closeIds = SessionWatchPolicy.DevicesToClose(devices.Select(device => device.DeviceId), playingIds);
            var closed = 0;
            foreach (var device in devices)
            {
                if (!closeIds.Contains(device.DeviceId, StringComparer.OrdinalIgnoreCase))
                {
                    continue;
                }

                await _sessions.Logout(device).ConfigureAwait(false);
                closed++;
            }

            var spared = sessions.Count(session => session.NowPlayingItem is not null);
            _store.AddAudit("SessionOthersClosed", TextSanitizer.Display(user.Username, 80) ?? name, $"Closed {closed} idle device(s). Spared {spared} playing session(s). Playback was not stopped.");
            return new SessionCloseResult(true, closed, spared, "Closed sessions that were not playing.");
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Could not close other sessions.");
            return new SessionCloseResult(false, 0, 0, "Could not close sessions.");
        }
    }

    private void NoteSessionWatch(ClientIdentity identity, string path, string? username, string outcome, PluginConfiguration config, DateTimeOffset now)
    {
        if (!config.SessionWatchEnabled || outcome != "Succeeded" || !IsCompletedSignIn(path))
        {
            return;
        }

        var name = username?.Trim();
        if (string.IsNullOrEmpty(name) || ThreatDetectors.IsHoneypot(name, config))
        {
            return;
        }

        var stored = TextSanitizer.Display(name, 80) ?? name;

        try
        {
            var address = identity.Address;
            var privileged = ExceptionPolicy.Classify(address, config) != ExceptionClass.None;
            var verified = identity.Trust == SourceTrust.Verified;
            if (address is not null && verified && !(config.SessionWatchSkipPrivilegedNetworks && privileged))
            {
                var update = _addresses.Note(stored, address);
                if (update.Changed)
                {
                    MarkAddressesDirty();
                }

                if (update.Alert && ReserveSessionNotice(stored, SessionWatchPolicy.NewAddress, config, now))
                {
                    _store.AddEvent(
                        new SecurityEvent
                        {
                            Kind = "SessionWatch",
                            Outcome = "Succeeded",
                            Username = stored,
                            Address = address,
                            Path = path,
                            Message = "Successful sign-in from an address this account had not used before. No session was closed.",
                            Enforced = false
                        },
                        config);
                }
            }
            else if (address is not null && verified && privileged)
            {
                var update = _addresses.Note(stored, address);
                if (update.Changed)
                {
                    MarkAddressesDirty();
                }
            }

            var count = _sessions.Sessions.Count(session => string.Equals(session.UserName, name, StringComparison.OrdinalIgnoreCase));
            if (SessionWatchPolicy.TooMany(count, config.SessionWatchConcurrent) && ReserveSessionNotice(stored, SessionWatchPolicy.ManySessions, config, now))
            {
                _store.AddEvent(
                    new SecurityEvent
                    {
                        Kind = "SessionWatch",
                        Outcome = "Succeeded",
                        Username = stored,
                        Address = address,
                        Path = path,
                        Message = $"This account has {count} concurrent sessions. Playback was not stopped.",
                        Enforced = false
                    },
                    config);
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Session watch could not record the sign-in.");
        }
    }

    private bool ReserveSessionNotice(string username, string kind, PluginConfiguration config, DateTimeOffset now)
    {
        var key = username + "|" + kind;
        var cooldown = TimeSpan.FromMinutes(SessionWatchPolicy.CooldownMinutes(config.SessionWatchCooldownMinutes));
        lock (_sessionGate)
        {
            if (_sessionNotices.TryGetValue(key, out var last) && now - last < cooldown)
            {
                return false;
            }

            _sessionNotices[key] = now;
            return true;
        }
    }

    private bool IsUnseen(string username, string address)
    {
        return !string.IsNullOrWhiteSpace(address)
            && _addresses.HasHistory(username)
            && !_addresses.Contains(username, address);
    }

    private IReadOnlyList<SessionWatchRow> ReadSessions()
    {
        var rows = new List<SessionWatchRow>();
        foreach (var session in _sessions.Sessions)
        {
            var name = session.UserName?.Trim();
            if (string.IsNullOrEmpty(name))
            {
                continue;
            }

            var title = session.NowPlayingItem?.Name;
            rows.Add(new SessionWatchRow(
                TextSanitizer.Display(name, 80) ?? name,
                TextSanitizer.Display(session.DeviceName, 80) ?? string.Empty,
                SessionWatchPolicy.NormalizeEndpoint(session.RemoteEndPoint) ?? string.Empty,
                session.NowPlayingItem is not null,
                TextSanitizer.Display(title, 80) ?? string.Empty,
                string.Empty));
        }

        return rows;
    }

    private static bool IsCompletedSignIn(string path)
    {
        return AuthPathClassifier.IsPasswordSignInPath(path)
            || path.Contains("/Users/AuthenticateWithQuickConnect", StringComparison.OrdinalIgnoreCase)
            || path.Contains("/QuickConnect/Authorize", StringComparison.OrdinalIgnoreCase);
    }

    public SecurityReport Report(int hours)
    {
        EnsureGeo();
        return SecurityReportBuilder.Build(_store.Events, _store.IncidentSnapshot(), _store.Bans, hours, DateTimeOffset.UtcNow, _geoHits, _geoLookups);
    }

    public EdgeSnippetResult EdgeSnippet()
    {
        return EdgeSnippetBuilder.Build(Config, ActiveBlocklist());
    }

    public IReadOnlyList<string> ActiveBlocklist()
    {
        var now = DateTimeOffset.UtcNow;
        return _store.Bans.Where(b => b.IsActive(now)).Select(b => b.Target).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
    }

    public void RecordEdgeObservation(string? address, string note)
    {
        var config = Config;
        _store.AddEvent(
            new SecurityEvent
            {
                Kind = "EdgeSignal",
                Outcome = "Unknown",
                Address = IpNormalizer.Normalize(address),
                Message = TextSanitizer.Display(note, 256) ?? "Edge signal",
                Trust = "Unknown"
            },
            config);
        Notify(new LiveNotification { Type = "event", Summary = "Edge signal recorded" });
    }

    public EngineSnapshot Snapshot()
    {
        return _store.Snapshot(DateTimeOffset.UtcNow);
    }

    public IReadOnlyCollection<BanRecord> Bans()
    {
        return _store.Bans;
    }

    public IReadOnlyList<SecurityEvent> Events()
    {
        return _store.Events;
    }

    public IReadOnlyList<PolicyAuditEntry> Audit()
    {
        return _store.Audit;
    }

    public IReadOnlyList<SecurityIncident> Incidents()
    {
        return _store.IncidentSnapshot();
    }

    public OperationResult<BanRecord> AddManualBan(string target, string reason, int? minutes)
    {
        var validation = BanTargetValidator.Validate(target);
        if (!validation.Ok || validation.Normalized is null)
        {
            return OperationResult<BanRecord>.Fail(validation.Message);
        }

        var record = new BanRecord
        {
            Target = validation.Normalized,
            Kind = validation.Kind,
            Reason = TextSanitizer.Display(reason, 256) ?? "Manual ban",
            ExpiresUtc = minutes is > 0 ? DateTimeOffset.UtcNow.AddMinutes(minutes.Value) : null,
            Strike = 0
        };
        _store.UpsertBan(record);
        _store.AddAudit("BanAdded", record.Target, record.Reason);
        _logger.LogInformation("Manual ban added for {Target}.", record.Target);
        Notify(new LiveNotification { Type = "ban", Summary = $"Ban added for {record.Target}" });
        return OperationResult<BanRecord>.Success(record, validation.Message);
    }

    public bool RemoveBan(string target)
    {
        var removed = _store.RemoveBan(target);
        if (removed)
        {
            _store.AddAudit("BanRemoved", target, "Administrator removed the ban.");
            Notify(new LiveNotification { Type = "ban", Summary = $"Ban removed for {target}" });
        }

        return removed;
    }

    private void RegisterFailure(ClientIdentity identity, string? username, PluginConfiguration config, DateTimeOffset now)
    {
        var ip = identity.Address!;
        var exception = ExceptionPolicy.Classify(ip, config);
        var ipWindow = _ipFailures.GetOrAdd(ip, _ => new AttemptWindow(TimeSpan.FromMinutes(Math.Max(1, config.FailureWindowMinutes))));
        var ipCount = ipWindow.Record(now);

        if (!string.IsNullOrWhiteSpace(username))
        {
            _accountIps.GetOrAdd(username, _ => new TimedSet())
                .Add(ip, now, TimeSpan.FromSeconds(Math.Max(15, config.DistributedWindowSeconds)));
            _ipUsernames.GetOrAdd(ip, _ => new TimedSet())
                .Add(username, now, TimeSpan.FromMinutes(Math.Max(1, config.PasswordSprayWindowMinutes)));
        }

        var honeypot = ThreatDetectors.IsHoneypot(username, config);
        if (honeypot)
        {
            TryHoneypotBan(identity, config, now, ip, exception);
            return;
        }

        if (!ExceptionPolicy.AllowsAutomaticBan(exception) || !_proxy.AllowsAutomaticIpBans(config, identity))
        {
            return;
        }

        if (ipCount < Math.Max(1, config.FailuresBeforeBan))
        {
            return;
        }

        // IPv6: a single address is trivially rotated by the client. When the admin opts in,
        // ban the containing /64 prefix (the typical end-user allocation) instead of skipping.
        // Without the opt-in we preserve the original fail-safe behavior: no automatic ban.
        if (IpNormalizer.IsIPv6(ip))
        {
            if (!config.AutomaticIpv6PrefixBan)
            {
                return;
            }

            var prefix = Ipv6Prefix.Of(ip, 64);
            if (prefix is null)
            {
                return;
            }

            var prefixState = _strikes.GetOrAdd(prefix, SeedStrike);
            var prefixStrike = BanSchedule.NextStrike(prefixState, config, now);
            var prefixMinutes = BanSchedule.DurationMinutes(config, prefixStrike);
            _store.UpsertBan(new BanRecord
            {
                Target = prefix,
                Kind = prefixStrike > 1 ? BanKind.Progressive : BanKind.AutomaticPrefix,
                Reason = $"Reached {ipCount} failed sign-in attempts from {ip} in the configured window.",
                ExpiresUtc = now.AddMinutes(prefixMinutes),
                Strike = prefixStrike,
                CreatedBy = "engine"
            });
            ipWindow.Clear();
            _store.AddAudit("AutomaticBan", prefix, $"Strike {prefixStrike}, {prefixMinutes} minutes (IPv6 /64).");
            _logger.LogWarning("Temporary /64 ban for {Prefix} for {Minutes} minutes (strike {Strike}).", prefix, prefixMinutes, prefixStrike);
            Notify(new LiveNotification { Type = "ban", Summary = $"Automatic /64 ban for {prefix} ({prefixMinutes}m, strike {prefixStrike})" });
            return;
        }

        var state = _strikes.GetOrAdd(ip, SeedStrike);
        var strike = BanSchedule.NextStrike(state, config, now);
        var minutes = BanSchedule.DurationMinutes(config, strike);
        _store.UpsertBan(new BanRecord
        {
            Target = ip,
            Kind = strike > 1 ? BanKind.Progressive : BanKind.AutomaticTemporary,
            Reason = $"Reached {ipCount} failed sign-in attempts in the configured window.",
            ExpiresUtc = now.AddMinutes(minutes),
            Strike = strike,
            CreatedBy = "engine"
        });
        ipWindow.Clear();
        _store.AddAudit("AutomaticBan", ip, $"Strike {strike}, {minutes} minutes.");
        _logger.LogWarning("Temporary ban for {IP} for {Minutes} minutes (strike {Strike}).", ip, minutes, strike);
        Notify(new LiveNotification { Type = "ban", Summary = $"Automatic ban for {ip} ({minutes}m, strike {strike})" });
    }

    public bool HoneypotNameMatchesUser()
    {
        var name = Config.HoneypotUsername?.Trim();
        if (string.IsNullOrEmpty(name))
        {
            return false;
        }

        try
        {
            return _users.GetUserByName(name) is not null;
        }
        catch (Exception ex)
        {
            // Fail-safe for the honeypot, not for the ban: a transient
            // lookup failure must not silently disable the instant ban.
            // If we cannot confirm the name matches a real user, treat
            // it as a non-match so the ban can arm. The alternative
            // (returning true) would disable the honeypot on every
            // transient error, which is the wrong failure mode.
            _logger.LogDebug(ex, "Honeypot user lookup threw; treating the name as a non-match so the ban stays armed.");
            return false;
        }
    }

    private void TryHoneypotBan(ClientIdentity identity, PluginConfiguration config, DateTimeOffset now, string ip, ExceptionClass exception)
    {
        var decision = HoneypotBanPolicy.Evaluate(
            config.HoneypotInstantBan,
            !string.IsNullOrWhiteSpace(config.HoneypotUsername),
            HoneypotNameMatchesUser(),
            identity.Trust == SourceTrust.Verified,
            !IpNormalizer.IsIPv6(ip),
            exception);
        if (!decision.Ban)
        {
            return;
        }

        var minutes = HoneypotBanPolicy.DurationMinutes(config.HoneypotBanMinutes);
        _store.UpsertBan(new BanRecord
        {
            Target = ip,
            Kind = BanKind.AutomaticTemporary,
            Reason = "Honeypot name was used. The Jellyfin account list was not changed.",
            ExpiresUtc = now.AddMinutes(minutes),
            Strike = 1,
            CreatedBy = "honeypot"
        });
        if (_ipFailures.TryGetValue(ip, out var window))
        {
            window.Clear();
        }

        _store.AddAudit("HoneypotInstantBan", ip, $"{minutes} minutes. The decoy name matched no Jellyfin user.");
        _logger.LogWarning("Honeypot instant ban for {IP} for {Minutes} minutes.", ip, minutes);
        Notify(new LiveNotification { Type = "ban", Summary = $"Honeypot instant ban for {ip} ({minutes}m)" });
    }

    private StrikeState SeedStrike(string ip)
    {
        var previous = _store.Bans
            .Where(b => b.Target.Equals(ip, StringComparison.OrdinalIgnoreCase) && b.Strike > 0)
            .OrderByDescending(b => b.CreatedUtc)
            .FirstOrDefault();
        return previous is null
            ? new StrikeState()
            : new StrikeState { Count = previous.Strike, LastUtc = previous.CreatedUtc };
    }

    private int Score(ClientIdentity identity, RiskAssessment assessment, DateTimeOffset now)
    {
        var historical = _history.Peek(identity.Address, now);
        var score = RiskScore.Combine(assessment, historical, identity.Trust);
        if (identity.Address is not null && assessment.RiskBand is not "Low")
        {
            _history.Remember(identity.Address, score, now);
        }

        return score;
    }

    private string? LookupCountry(string? address)
    {
        EnsureGeo();
        if (_geo.Count == 0 || string.IsNullOrEmpty(address))
        {
            return null;
        }

        Interlocked.Increment(ref _geoLookups);
        var hit = LocalGeoDirectory.Lookup(address, _geo);
        if (hit is not null)
        {
            Interlocked.Increment(ref _geoHits);
            return hit.Country;
        }

        return null;
    }

    private void EnsureGeo()
    {
        var path = Config.LocalGeoFile ?? string.Empty;
        if (path == _geoPath)
        {
            return;
        }

        _geoPath = path;
        try
        {
            _geo = LocalGeoDirectory.Load(path);
        }
        catch (Exception ex)
        {
            _geo = [];
            _logger.LogDebug(ex, "Local geo file could not be read.");
        }
    }

    /// <summary>Reads the configured local geo file and returns the ranges stored under one country name.</summary>
    public OperationResult<string> GeoRangesFor(string? name)
    {
        EnsureGeo();
        if (_geo.Count == 0)
        {
            return OperationResult<string>.Fail("No local geo file is loaded. Point to one in the More tab, save, and try again.");
        }

        if (string.IsNullOrWhiteSpace(name))
        {
            return OperationResult<string>.Fail("Type a country name first.");
        }

        var networks = _geo
            .Where(g => g.Country.Equals(name.Trim(), StringComparison.OrdinalIgnoreCase))
            .Select(g => g.Network)
            .Distinct(StringComparer.Ordinal)
            .Take(2000)
            .ToList();
        if (networks.Count == 0)
        {
            return OperationResult<string>.Fail($"No ranges for \"{name.Trim()}\" in the geo file. Check the country text in the file's second column.");
        }

        return OperationResult<string>.Success(string.Join(", ", networks), networks.Count + " ranges for \"" + name.Trim() + "\".");
    }

    private void MarkAddressesDirty()
    {
        var now = DateTimeOffset.UtcNow;
        lock (_addressFlushGate)
        {
            _addressesDirty = true;
            // Flush at most once per 30 seconds to reduce I/O during bursts.
            if (now - _lastAddressFlush >= TimeSpan.FromSeconds(30))
            {
                _store.WriteKnownAddresses(_addresses.Export());
                _addressesDirty = false;
                _lastAddressFlush = now;
            }
        }
    }

    /// <summary>
    /// Call after config changes or on shutdown to persist any pending address updates.
    /// </summary>
    public void FlushPendingWrites()
    {
        lock (_addressFlushGate)
        {
            if (_addressesDirty)
            {
                _store.WriteKnownAddresses(_addresses.Export());
                _addressesDirty = false;
                _lastAddressFlush = DateTimeOffset.UtcNow;
            }
        }
    }
}

public sealed record BanDecision(bool Block, BanRecord? Ban, string Reason)
{
    public static BanDecision Allow(string reason) => new(false, null, reason);

    public static BanDecision Deny(BanRecord ban, string reason) => new(true, ban, reason);
}

public readonly record struct ReconLimitDecision(bool Block, int RetryAfterSeconds)
{
    public static ReconLimitDecision Allow => new(false, 0);
}

public sealed record ReconLimitedRow(string Address, int RemainingSeconds);

public sealed record OperationResult<T>(bool Ok, T? Value, string Message)
{
    public static OperationResult<T> Success(T value, string message) => new(true, value, message);

    public static OperationResult<T> Fail(string message) => new(false, default, message);
}
