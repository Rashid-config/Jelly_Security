using System.Reflection;
using System.Text;
using Jellyfin.Plugin.JellySecurity.Core.Detection;
using Jellyfin.Plugin.JellySecurity.Core.Edge;
using Jellyfin.Plugin.JellySecurity.Core.Engine;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Jellyfin.Plugin.JellySecurity.Api;

/// <summary>
/// Admin-only snapshot of the engine. Settings still use the standard plugin configuration API.
/// </summary>
[ApiController]
[Authorize(Policy = "RequiresElevation")]
[Route("JellySecurity")]
public sealed class SecurityDashboardController : ControllerBase
{
    private readonly SecurityEngine _engine;
    private static readonly string PluginVersion =
        typeof(Plugin).Assembly.GetName().Version?.ToString() ?? "0.0.0.0";

    public SecurityDashboardController(SecurityEngine engine)
    {
        _engine = engine;
    }

    [HttpGet("status")]
    public ActionResult<object> Status()
    {
        var config = _engine.Config;
        var snapshot = _engine.Snapshot();
        var health = _engine.Health();
        return CamelJson.Ok(new
        {
            mode = config.Mode.ToString(),
            health.EngineState,
            health.ProxyStatus,
            health.AutomaticEnforcementReady,
            health.PreAuthLockoutProtectionProven,
            health.Warnings,
            automaticIpBans = config.AutomaticIpBans,
            applyManualBans = config.ApplyManualBans,
            targetJellyfin = PluginConstants.TargetJellyfinVersion,
            pluginVersion = PluginVersion,
            snapshot.ActiveBans,
            snapshot.EventsLast24Hours,
            snapshot.FailedLast24Hours,
            snapshot.BlockedLast24Hours,
            snapshot.IncidentsLast24Hours,
            passwordDelayEnabled = config.PasswordDelayEnabled,
            passwordDelays = _engine.PasswordDelaySnapshot(),
            accountCooldownEnabled = config.AccountCooldownEnabled,
            accountCooldowns = _engine.AccountCooldownSnapshot(),
            honeypotInstantBan = config.HoneypotInstantBan,
            honeypotNameCollides = _engine.HoneypotNameMatchesUser(),
            lockoutWatchEnabled = config.LockoutWatchEnabled,
            lockoutWatch = _engine.LockoutWatchSnapshot(),
            edgeSnippetEnabled = config.EdgeSnippetEnabled,
            edgeSnippetTarget = config.EdgeSnippetTarget,
            sessionWatchEnabled = config.SessionWatchEnabled,
            sessionWatch = _engine.SessionWatchSnapshot(),
            reconWatchEnabled = config.ReconWatchEnabled,
            reconEnforce = config.ReconEnforce,
            reconLimited = _engine.ReconLimitedRows()
        });
    }

    [HttpGet("snippet")]
    public ActionResult<EdgeSnippetResult> Snippet()
    {
        return Ok(_engine.EdgeSnippet());
    }

    [HttpGet("events")]
    public ActionResult<object> Events([FromQuery] string? outcome, [FromQuery] string? address, [FromQuery] string? username, [FromQuery] string? kind)
    {
        var items = EventQuery.Filter(_engine.Events(), outcome, address, username, kind)
            .Select(e => new
            {
                e.TimestampUtc,
                e.Kind,
                e.Outcome,
                e.Username,
                e.Address,
                e.Path,
                e.Trust,
                e.Message,
                e.Enforced,
                e.RiskBand,
                e.RecommendedAction
            });
        return CamelJson.Ok(items);
    }

    [HttpGet("incidents")]
    public ActionResult<object> Incidents()
    {
        var items = _engine.Incidents()
            .OrderByDescending(i => i.LastUtc)
            .Take(100)
            .Select(i => new
            {
                i.Id,
                i.DetectorId,
                i.Subject,
                i.RiskBand,
                i.RecommendedAction,
                i.Count,
                i.FirstUtc,
                i.LastUtc,
                i.Explanation
            });
        return CamelJson.Ok(items);
    }

    [HttpGet("timeline")]
    public ActionResult<object> Timeline()
    {
        var stories = Core.Reports.TimelineBuilder.Build(
            _engine.Events(),
            _engine.Incidents(),
            _engine.Bans());

        var result = stories.Select(s => new
        {
            s.Subject,
            s.GroupBy,
            s.FirstUtc,
            s.LastUtc,
            s.AttemptCount,
            s.FailedCount,
            s.BlockedCount,
            s.DistinctUsernames,
            s.DistinctAddresses,
            s.HighestRiskBand,
            s.WasBanned,
            s.BanKind,
            detectors = s.Detectors,
            duration = s.Duration,
            steps = s.Steps.Select(step => new
            {
                step.TimestampUtc,
                step.Type,
                step.Outcome,
                step.Username,
                step.Address,
                step.RiskBand,
                step.Message,
                step.Enforced
            })
        });

        return CamelJson.Ok(result);
    }

    [HttpGet("events.csv")]
    public ActionResult ExportEvents([FromQuery] string? outcome, [FromQuery] string? address, [FromQuery] string? username, [FromQuery] string? kind)
    {
        var csv = EventQuery.ToCsv(EventQuery.Filter(_engine.Events(), outcome, address, username, kind));
        return File(Encoding.UTF8.GetBytes(csv), "text/csv", "jelly-security-events.csv");
    }

    [HttpGet("geo/lookup")]
    public ActionResult<object> GeoLookup([FromQuery] string? name)
    {
        var result = _engine.GeoRangesFor(name);
        if (!result.Ok)
        {
            return CamelJson.Ok(new { ok = false, message = result.Message, ranges = string.Empty });
        }

        var count = string.IsNullOrEmpty(result.Value) ? 0 : result.Value.Split(',').Length;
        return CamelJson.Ok(new { ok = true, message = result.Message, ranges = result.Value, count });
    }

    [HttpGet("audit")]
    public ActionResult<object> Audit()
    {
        var items = _engine.Audit()
            .OrderByDescending(e => e.TimestampUtc)
            .Take(100)
            .Select(e => new { e.TimestampUtc, e.Action, e.Target, e.Detail });
        return CamelJson.Ok(items);
    }

    [HttpGet("bans")]
    public ActionResult<object> Bans()
    {
        var now = DateTimeOffset.UtcNow;
        var items = _engine.Bans()
            .OrderByDescending(b => b.CreatedUtc)
            .Select(b => new
            {
                b.Target,
                kind = b.Kind.ToString(),
                b.Reason,
                b.CreatedUtc,
                b.ExpiresUtc,
                b.CreatedBy,
                active = b.IsActive(now)
            });
        return CamelJson.Ok(items);
    }

    [HttpPost("bans")]
    public ActionResult<object> AddBan([FromBody] ManualBanRequest request)
    {
        var result = _engine.AddManualBan(request.Target, request.Reason ?? string.Empty, request.Minutes);
        if (!result.Ok)
        {
            return BadRequest(new { result.Message });
        }

        return Ok(result.Value);
    }

    [HttpGet("report")]
    public ActionResult<object> Report([FromQuery] int hours = 24)
    {
        return CamelJson.Ok(_engine.Report(hours));
    }

    [HttpGet("posture")]
    public ActionResult<object> Posture()
    {
        return CamelJson.Ok(_engine.Posture());
    }

    [HttpGet("backup")]
    public ActionResult Backup([FromQuery] bool includeSecrets = false)
    {
        var document = _engine.CreateBackup(includeSecrets);
        var json = ConfigBackup.Serialize(document);
        return File(Encoding.UTF8.GetBytes(json), "application/json", "jelly-security-backup.json");
    }

    [HttpPost("backup/preview")]
    public ActionResult<object> PreviewBackup([FromBody] BackupTextRequest request)
    {
        var preview = _engine.PreviewBackup(request.Json ?? string.Empty);
        return preview.Ok ? Ok(preview) : BadRequest(preview);
    }

    [HttpPost("backup/restore")]
    public ActionResult<object> RestoreBackup([FromBody] BackupTextRequest request)
    {
        var result = _engine.ApplyBackup(request.Json ?? string.Empty);
        if (!result.Ok)
        {
            return BadRequest(new { result.Message });
        }

        return Ok(new { result.Message, bans = result.Value });
    }

    [HttpDelete("bans")]
    public ActionResult RemoveBan([FromQuery] string target)
    {
        if (string.IsNullOrWhiteSpace(target) || !_engine.RemoveBan(target))
        {
            return NotFound();
        }

        return NoContent();
    }

    [HttpPost("cooldowns/clear")]
    public ActionResult<object> ClearCooldown([FromBody] ClearCooldownRequest request)
    {
        if (request is null || string.IsNullOrWhiteSpace(request.Username))
        {
            return BadRequest(new { Message = "Username is required." });
        }

        return Ok(new { removed = _engine.ClearAccountCooldown(request.Username) });
    }

    /// <summary>
    /// Ends the API scan slow-down (429 cooldown) for one address early.
    /// The recon watch keeps observing the address afterwards.
    /// </summary>
    [HttpPost("recon/clear")]
    public ActionResult<object> ClearReconLimit([FromBody] ClearReconRequest request)
    {
        if (request is null || string.IsNullOrWhiteSpace(request.Address))
        {
            return BadRequest(new { Message = "Address is required." });
        }

        return Ok(new { removed = _engine.ClearReconLimit(request.Address) });
    }

    [HttpPost("sessions/close-others")]
    public async Task<ActionResult<object>> CloseOtherSessions([FromBody] SessionCloseRequest request)
    {
        if (request is null || string.IsNullOrWhiteSpace(request.Username))
        {
            return BadRequest(new { Message = "Username is required." });
        }

        var result = await _engine.CloseOtherSessionsAsync(request.Username).ConfigureAwait(false);
        if (!result.Ok)
        {
            return BadRequest(new { result.Message });
        }

        return Ok(new { closed = result.Closed, sparedPlayback = result.SparedPlayback, result.Message });
    }

    /// <summary>
    /// Server-Sent Events stream for live dashboard updates. The frontend opens
    /// an EventSource on this URL and receives a notification whenever a sign-in
    /// event is recorded, a ban is added or removed, or an automatic ban fires.
    /// Each notification is a small JSON object with type, summary, and timestamp.
    /// The stream stays open until the client disconnects. Falls back to 30s
    /// polling if SSE is unavailable (e.g. behind a proxy that buffers responses).
    /// </summary>
    [HttpGet("stream")]
    public async Task Stream(CancellationToken cancellationToken)
    {
        var hub = _engine.Hub;
        if (hub is null)
        {
            Response.StatusCode = 503;
            return;
        }

        Response.Headers.ContentType = "text/event-stream";
        Response.Headers.CacheControl = "no-cache";
        Response.Headers.Connection = "keep-alive";
        Response.Headers["X-Accel-Buffering"] = "no"; // nginx: don't buffer SSE

        // Send an initial comment so the client knows the stream is alive.
        await Response.WriteAsync(": connected\n\n", cancellationToken).ConfigureAwait(false);
        await Response.Body.FlushAsync(cancellationToken).ConfigureAwait(false);

        try
        {
            await foreach (var notification in hub.Subscribe(cancellationToken).ConfigureAwait(false))
            {
                var json = System.Text.Json.JsonSerializer.Serialize(new
                {
                    notification.Type,
                    notification.Summary,
                    timestampUtc = notification.TimestampUtc
                });
                await Response.WriteAsync($"data: {json}\n\n", cancellationToken).ConfigureAwait(false);
                await Response.Body.FlushAsync(cancellationToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
            // Client disconnected — normal SSE lifecycle.
        }
    }
}

public sealed class SessionCloseRequest
{
    public string? Username { get; set; }
}

public sealed class ClearCooldownRequest
{
    public string Username { get; set; } = string.Empty;
}

public sealed class ClearReconRequest
{
    public string Address { get; set; } = string.Empty;
}

public sealed class ManualBanRequest
{
    public string Target { get; set; } = string.Empty;

    public string? Reason { get; set; }

    public int? Minutes { get; set; }
}

public sealed class BackupTextRequest
{
    public string? Json { get; set; }
}
