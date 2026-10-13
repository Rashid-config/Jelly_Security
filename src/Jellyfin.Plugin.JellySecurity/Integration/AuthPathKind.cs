namespace Jellyfin.Plugin.JellySecurity.Integration;

public enum AuthPathKind
{
    None = 0,
    Password = 1,
    QuickConnect = 2,
    PasswordReset = 3,
    Admin = 4,
    Session = 5
}
