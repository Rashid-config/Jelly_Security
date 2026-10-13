namespace Jellyfin.Plugin.JellySecurity.Core.Policies;

public enum BanKind
{
    AutomaticTemporary = 0,
    Progressive = 1,
    Manual = 2,
    Cidr = 3,
    Geo = 4,
    AutomaticPrefix = 5
}
