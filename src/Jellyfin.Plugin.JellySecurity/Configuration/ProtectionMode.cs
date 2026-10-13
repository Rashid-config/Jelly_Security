namespace Jellyfin.Plugin.JellySecurity.Configuration;

/// <summary>
/// Operating mode. The first run is always monitor-only.
/// </summary>
public enum ProtectionMode
{
    MonitorOnly = 0,
    Balanced = 1,
    Strict = 2,
    Custom = 3,
    Emergency = 4
}
