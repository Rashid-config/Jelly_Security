using Jellyfin.Plugin.JellySecurity.Core.Engine;
using Jellyfin.Plugin.JellySecurity.Storage;
using Microsoft.Extensions.Hosting;

namespace Jellyfin.Plugin.JellySecurity.Integration;

/// <summary>
/// Flushes debounced writes on graceful shutdown. Events persist at most once
/// per 5 seconds and known addresses at most once per 30 seconds during
/// operation; this closes the last window so a restart does not drop them.
/// </summary>
public sealed class PluginFlushService : IHostedService
{
    private readonly SecurityEngine _engine;
    private readonly SecurityStore _store;

    public PluginFlushService(SecurityEngine engine, SecurityStore store)
    {
        _engine = engine;
        _store = store;
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        try
        {
            _engine.FlushPendingWrites();
            _store.FlushPendingEventWrites();
        }
        catch (Exception)
        {
            // Shutdown must not fail over a flush.
        }

        return Task.CompletedTask;
    }
}
