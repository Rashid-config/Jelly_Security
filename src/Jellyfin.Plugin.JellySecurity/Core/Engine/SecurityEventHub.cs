using System.Threading.Channels;
using Jellyfin.Plugin.JellySecurity.Core.Detection;

namespace Jellyfin.Plugin.JellySecurity.Core.Engine;

/// <summary>
/// A lightweight pub/sub hub that pushes live notifications to SSE clients.
/// The engine publishes a <see cref="LiveNotification"/> whenever a sign-in
/// event is recorded, a ban is added or removed, or an incident is raised.
/// Each subscriber gets its own channel so disconnecting one client does not
/// affect others.
/// </summary>
public sealed class SecurityEventHub : IDisposable
{
    private readonly List<Channel<LiveNotification>> _subscribers = new();
    private readonly object _lock = new();

    /// <summary>
    /// Publishes a notification to all connected clients. Non-blocking — if no
    /// clients are connected, the notification is silently dropped.
    /// </summary>
    public void Publish(LiveNotification notification)
    {
        List<Channel<LiveNotification>> snapshot;
        lock (_lock)
        {
            snapshot = _subscribers.ToList();
        }

        foreach (var channel in snapshot)
        {
            // TryWrite returns false if the channel is full or closed.
            // Either way, we don't block — the client will miss this one
            // and catch up on the next poll.
            channel.Writer.TryWrite(notification);
        }
    }

    /// <summary>
    /// Returns a reader that yields notifications as they arrive. Each SSE
    /// client gets its own channel so one slow client does not block others.
    /// </summary>
    public IAsyncEnumerable<LiveNotification> Subscribe(CancellationToken cancellationToken)
    {
        var channel = Channel.CreateUnbounded<LiveNotification>(new UnboundedChannelOptions
        {
            SingleReader = true,
            SingleWriter = false
        });

        lock (_lock)
        {
            _subscribers.Add(channel);
        }

        // Remove the channel when the token cancels so we don't leak memory.
        cancellationToken.Register(() =>
        {
            lock (_lock)
            {
                _subscribers.Remove(channel);
            }
            channel.Writer.TryComplete();
        });

        return channel.Reader.ReadAllAsync(cancellationToken);
    }

    public void Dispose()
    {
        lock (_lock)
        {
            foreach (var channel in _subscribers)
            {
                channel.Writer.TryComplete();
            }
            _subscribers.Clear();
        }
    }
}

/// <summary>
/// One notification sent to live dashboard clients. Small by design — the
/// frontend uses it as a "refresh now" signal, not as a full data payload.
/// </summary>
public sealed class LiveNotification
{
    /// <summary>
    /// "event", "ban", "incident", or "status" — tells the frontend what to refresh.
    /// </summary>
    public string Type { get; set; } = string.Empty;

    /// <summary>
    /// A short human-readable summary, e.g. "Failed sign-in for admin from 203.0.113.10".
    /// </summary>
    public string Summary { get; set; } = string.Empty;

    /// <summary>
    /// UTC timestamp of the notification.
    /// </summary>
    public DateTimeOffset TimestampUtc { get; set; } = DateTimeOffset.UtcNow;
}
