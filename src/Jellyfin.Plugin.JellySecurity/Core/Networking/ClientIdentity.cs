namespace Jellyfin.Plugin.JellySecurity.Core.Networking;

public sealed record ClientIdentity(
    string? Address,
    string RemoteSocketAddress,
    SourceTrust Trust,
    string Reason,
    bool UsedForwardedHeader,
    int ForwardedHopCount = 0,
    bool AmbiguousForwardedChain = false);
