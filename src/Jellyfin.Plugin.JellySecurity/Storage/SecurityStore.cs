using System.Collections.Concurrent;
using System.Text.Json;
using Jellyfin.Plugin.JellySecurity.Configuration;
using Jellyfin.Plugin.JellySecurity.Core.Detection;
using Jellyfin.Plugin.JellySecurity.Core.Policies;
using MediaBrowser.Common.Configuration;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.JellySecurity.Storage;

/// <summary>
/// Plugin-owned JSON files. This store never writes to jellyfin.db.
/// </summary>
public sealed class SecurityStore
{
    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true };

    private readonly string _bansPath;
    private readonly string _eventsPath;
    private readonly string _auditPath;
    private readonly string _incidentsPath;
    private readonly string _knownAddressesPath;
    private readonly ILogger<SecurityStore> _logger;
    private readonly object _fileLock = new();
    private readonly ConcurrentDictionary<string, BanRecord> _bans = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<SecurityEvent> _events = [];
    private readonly List<PolicyAuditEntry> _audit = [];
    private readonly List<SecurityIncident> _incidents = [];

    private bool _persist = true;
    private readonly HashSet<string> _brokenFiles = new(StringComparer.OrdinalIgnoreCase);
    private bool _eventsDirty;
    private DateTimeOffset _lastEventFlush = DateTimeOffset.UtcNow;
    private readonly object _eventFlushGate = new();

    public SecurityStore(IApplicationPaths applicationPaths, ILogger<SecurityStore> logger)
    {
        _logger = logger;
        var directory = Path.Combine(applicationPaths.PluginConfigurationsPath, "JellySecurity");
        try
        {
            Directory.CreateDirectory(directory);
        }
        catch (Exception ex)
        {
            _persist = false;
            logger.LogWarning(ex, "Jelly Security store directory is not writable. Monitoring continues without persistence.");
        }

        _bansPath = Path.Combine(directory, "bans.json");
        _eventsPath = Path.Combine(directory, "events.json");
        _auditPath = Path.Combine(directory, "audit.json");
        _incidentsPath = Path.Combine(directory, "incidents.json");
        _knownAddressesPath = Path.Combine(directory, "known-addresses.json");
        if (_persist)
        {
            Load();
        }
    }

    public IReadOnlyCollection<BanRecord> Bans => _bans.Values.ToArray();

    public IReadOnlyList<PolicyAuditEntry> Audit
    {
        get
        {
            lock (_audit)
            {
                return _audit.ToArray();
            }
        }
    }

    public IReadOnlyList<SecurityIncident> IncidentSnapshot()
    {
        lock (_incidents)
        {
            return _incidents.Select(i => i.Clone()).ToArray();
        }
    }

    public SecurityIncident? RecordIncident(DetectorSignal primary, RiskAssessment assessment, PluginConfiguration config, DateTimeOffset now)
    {
        SecurityIncident? incident;
        lock (_incidents)
        {
            incident = AlertAggregator.Record(_incidents, primary, assessment, config, now);
        }

        if (incident is not null)
        {
            SaveIncidents();
        }

        return incident;
    }

    public IReadOnlyList<SecurityEvent> Events
    {
        get
        {
            lock (_events)
            {
                return _events.ToArray();
            }
        }
    }

    public void UpsertBan(BanRecord record)
    {
        _bans[record.Target] = record;
        SaveBans();
    }

    public void ReplaceBans(IEnumerable<BanRecord> bans)
    {
        _bans.Clear();
        foreach (var ban in bans)
        {
            if (string.IsNullOrWhiteSpace(ban.Target))
            {
                continue;
            }

            _bans[ban.Target] = ban;
        }

        SaveBans();
    }

    public bool RemoveBan(string target)
    {
        var removed = _bans.TryRemove(target, out _);
        if (removed)
        {
            SaveBans();
        }

        return removed;
    }

    public BanRecord? FindActiveBan(string? target, DateTimeOffset now)
    {
        if (string.IsNullOrEmpty(target))
        {
            return null;
        }

        if (_bans.TryGetValue(target, out var record) && record.IsActive(now))
        {
            return record;
        }

        foreach (var ban in _bans.Values)
        {
            if ((ban.Kind == BanKind.Cidr || ban.Kind == BanKind.AutomaticPrefix) && ban.IsActive(now) && Core.Networking.CidrMatcher.Matches(target, ban.Target))
            {
                return ban;
            }
        }

        return null;
    }

    public void AddEvent(SecurityEvent item, PluginConfiguration config)
    {
        lock (_events)
        {
            _events.Add(item);
            var cutoff = DateTimeOffset.UtcNow.AddDays(-Math.Max(1, config.EventRetentionDays));
            _events.RemoveAll(e => e.TimestampUtc < cutoff);
            var max = Math.Clamp(config.MaxEvents, 100, 100000);
            if (_events.Count > max)
            {
                _events.RemoveRange(0, _events.Count - max);
            }
        }

        MarkEventsDirty();
    }

    /// <summary>
    /// Debounces event writes so a burst of failed sign-ins does not write
    /// events.json on every single attempt. Flushes at most once per 5 seconds.
    /// </summary>
    private void MarkEventsDirty()
    {
        var now = DateTimeOffset.UtcNow;
        lock (_eventFlushGate)
        {
            _eventsDirty = true;
            if (now - _lastEventFlush >= TimeSpan.FromSeconds(5))
            {
                SaveEvents();
                _eventsDirty = false;
                _lastEventFlush = now;
            }
        }
    }

    /// <summary>
    /// Call on shutdown or config change to persist any pending event writes.
    /// </summary>
    public void FlushPendingEventWrites()
    {
        lock (_eventFlushGate)
        {
            if (_eventsDirty)
            {
                SaveEvents();
                _eventsDirty = false;
                _lastEventFlush = DateTimeOffset.UtcNow;
            }
        }
    }

    public void AddAudit(string action, string target, string detail)
    {
        lock (_audit)
        {
            _audit.Add(new PolicyAuditEntry
            {
                Action = action,
                Target = TextSanitizer.Display(target, 256) ?? string.Empty,
                Detail = TextSanitizer.Display(detail, 512) ?? string.Empty
            });
            if (_audit.Count > 2000)
            {
                _audit.RemoveRange(0, _audit.Count - 2000);
            }
        }

        lock (_fileLock)
        {
            Write(_auditPath, Audit);
        }
    }

    public void SaveIncidents()
    {
        lock (_fileLock)
        {
            IReadOnlyList<SecurityIncident> copy;
            lock (_incidents)
            {
                if (_incidents.Count > 2000)
                {
                    _incidents.RemoveRange(0, _incidents.Count - 2000);
                }

                copy = _incidents.ToArray();
            }

            Write(_incidentsPath, copy);
        }
    }

    public Dictionary<string, List<string>> ReadKnownAddresses()
    {
        var map = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        if (!File.Exists(_knownAddressesPath))
        {
            return map;
        }

        try
        {
            var saved = JsonSerializer.Deserialize<Dictionary<string, List<string>>>(File.ReadAllText(_knownAddressesPath));
            if (saved is null)
            {
                return map;
            }

            foreach (var pair in saved)
            {
                if (!string.IsNullOrWhiteSpace(pair.Key) && pair.Value is not null)
                {
                    map[pair.Key] = pair.Value;
                }
            }
        }
        catch (Exception ex)
        {
            _brokenFiles.Add(_knownAddressesPath);
            _logger.LogWarning(ex, "Could not read {Path}. The file was kept and will not be overwritten.", _knownAddressesPath);
        }

        return map;
    }

    public void WriteKnownAddresses(IReadOnlyDictionary<string, List<string>> map)
    {
        Write(_knownAddressesPath, map);
    }

    public EngineSnapshot Snapshot(DateTimeOffset now)
    {
        var activeBans = _bans.Values.Count(b => b.IsActive(now));
        int events24h;
        int failed24h;
        int blocked24h;
        int incidents24h;
        lock (_events)
        {
            var since = now.AddHours(-24);
            events24h = _events.Count(e => e.TimestampUtc >= since);
            failed24h = _events.Count(e => e.TimestampUtc >= since && e.Outcome == "Failed");
            blocked24h = _events.Count(e => e.TimestampUtc >= since && e.Outcome == "Blocked");
        }

        lock (_incidents)
        {
            incidents24h = _incidents.Count(i => i.LastUtc >= now.AddHours(-24));
        }

        return new EngineSnapshot(activeBans, events24h, failed24h, blocked24h, incidents24h);
    }

    private void Load()
    {
        ReadFile(_bansPath, json =>
        {
            var bans = JsonSerializer.Deserialize<List<BanRecord>>(json);
            if (bans is null)
            {
                return;
            }

            foreach (var ban in bans)
            {
                if (string.IsNullOrWhiteSpace(ban.Target))
                {
                    continue;
                }

                _bans[ban.Target] = ban;
            }
        });

        ReadFile(_eventsPath, json =>
        {
            var events = JsonSerializer.Deserialize<List<SecurityEvent>>(json);
            if (events is null)
            {
                return;
            }

            lock (_events)
            {
                _events.AddRange(events);
            }
        });

        ReadFile(_auditPath, json =>
        {
            var audit = JsonSerializer.Deserialize<List<PolicyAuditEntry>>(json);
            if (audit is null)
            {
                return;
            }

            lock (_audit)
            {
                _audit.AddRange(audit);
            }
        });

        ReadFile(_incidentsPath, json =>
        {
            var incidents = JsonSerializer.Deserialize<List<SecurityIncident>>(json);
            if (incidents is null)
            {
                return;
            }

            lock (_incidents)
            {
                _incidents.AddRange(incidents);
            }
        });
    }

    private void ReadFile(string path, Action<string> apply)
    {
        if (!File.Exists(path))
        {
            return;
        }

        try
        {
            apply(File.ReadAllText(path));
        }
        catch (Exception ex)
        {
            // Only this file is marked broken — a corrupt events.json must not
            // silently stop bans.json from persisting.
            _brokenFiles.Add(path);
            _logger.LogWarning(ex, "Could not read {Path}. The file was kept and will not be overwritten by an empty store.", path);
        }
    }

    private void SaveBans()
    {
        // Snapshot and write under one lock so a later mutation's write cannot
        // land before an earlier snapshot's write and lose an entry on disk.
        lock (_fileLock)
        {
            Write(_bansPath, _bans.Values.ToArray());
        }
    }

    private void SaveEvents()
    {
        lock (_fileLock)
        {
            IReadOnlyList<SecurityEvent> copy;
            lock (_events)
            {
                copy = _events.ToArray();
            }

            Write(_eventsPath, copy);
        }
    }

    private void Write<T>(string path, T value)
    {
        if (!_persist || _brokenFiles.Contains(path))
        {
            return;
        }

        try
        {
            var json = JsonSerializer.Serialize(value, Json);
            lock (_fileLock)
            {
                // Atomic write: write to a temp file, then rename. This prevents
                // a corrupt file if the process stops mid-write.
                var temp = path + ".tmp";
                File.WriteAllText(temp, json);
                if (File.Exists(path))
                {
                    File.Replace(temp, path, null);
                }
                else
                {
                    File.Move(temp, path);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not write {Path}.", path);
        }
    }
}

public sealed record EngineSnapshot(int ActiveBans, int EventsLast24Hours, int FailedLast24Hours, int BlockedLast24Hours, int IncidentsLast24Hours);
