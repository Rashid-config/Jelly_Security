namespace Jellyfin.Plugin.JellySecurity.Core.Engine;

public sealed record PostureFinding(string Id, string Severity, string Title, string Detail, bool Proven);
