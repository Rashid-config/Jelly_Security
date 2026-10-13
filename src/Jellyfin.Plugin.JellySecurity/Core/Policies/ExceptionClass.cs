namespace Jellyfin.Plugin.JellySecurity.Core.Policies;

public enum ExceptionClass
{
    None = 0,
    Loopback = 1,
    Administrative = 2,
    Trusted = 3,
    Monitoring = 4
}
