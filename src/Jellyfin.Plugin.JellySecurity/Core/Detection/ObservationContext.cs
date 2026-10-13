using Jellyfin.Plugin.JellySecurity.Core.Networking;
using Jellyfin.Plugin.JellySecurity.Core.Policies;

namespace Jellyfin.Plugin.JellySecurity.Core.Detection;

public sealed record ObservationContext(
    ClientIdentity Identity,
    string? Username,
    string Outcome,
    string Path,
    int FailuresFromAddress,
    int DistinctIpsForUsername,
    int DistinctUsernamesFromAddress,
    ExceptionClass Exception,
    DateTimeOffset Now);
