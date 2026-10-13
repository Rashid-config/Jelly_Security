using Jellyfin.Plugin.JellySecurity.Core.Edge;
using Jellyfin.Plugin.JellySecurity.Core.Engine;
using Jellyfin.Plugin.JellySecurity.Core.RateLimiting;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Jellyfin.Plugin.JellySecurity.Api;

/// <summary>
/// Limited reverse-proxy channel. Off by default. Does not change Nginx or Caddy files.
/// </summary>
[ApiController]
[AllowAnonymous]
[Route("JellySecurity/edge")]
public sealed class EdgeChannelController : ControllerBase
{
    private static readonly BoundedMap<AttemptWindow> _eventRateLimits = new(1000);
    private const int MaxEdgeEventsPerMinute = 60;

    private readonly SecurityEngine _engine;

    public EdgeChannelController(SecurityEngine engine)
    {
        _engine = engine;
    }

    [HttpGet("blocklist")]
    public ActionResult<object> Blocklist()
    {
        if (!Authorized())
        {
            return Unauthorized();
        }

        return Ok(_engine.ActiveBlocklist());
    }

    [HttpGet("deny.txt")]
    public ActionResult Deny([FromQuery] string? format)
    {
        if (!Authorized())
        {
            return Unauthorized();
        }

        if (!EdgeDenyText.TryFormat(format, _engine.ActiveBlocklist(), out var text))
        {
            return BadRequest();
        }

        return Content(text, "text/plain; charset=utf-8");
    }

    [HttpPost("events")]
    public ActionResult Accept([FromBody] EdgeEventRequest request)
    {
        if (!Authorized())
        {
            return Unauthorized();
        }

        var peer = Jellyfin.Plugin.JellySecurity.Core.Networking.IpNormalizer.Normalize(HttpContext.Connection.RemoteIpAddress?.ToString()) ?? "unknown";
        var window = _eventRateLimits.GetOrAdd(peer, _ => new AttemptWindow(TimeSpan.FromMinutes(1)));
        if (window.Record(DateTimeOffset.UtcNow) > MaxEdgeEventsPerMinute)
        {
            return StatusCode(StatusCodes.Status429TooManyRequests);
        }

        _engine.RecordEdgeObservation(request.Address, request.Note ?? "edge");
        return Accepted();
    }

    private bool Authorized()
    {
        Request.Headers.TryGetValue("X-Jelly-Security-Edge-Key", out var key);
        var peer = HttpContext.Connection.RemoteIpAddress?.ToString();
        return EdgeAccess.IsAuthorized(_engine.Config, key.ToString(), peer);
    }
}

public sealed class EdgeEventRequest
{
    public string? Address { get; set; }

    public string? Note { get; set; }
}
