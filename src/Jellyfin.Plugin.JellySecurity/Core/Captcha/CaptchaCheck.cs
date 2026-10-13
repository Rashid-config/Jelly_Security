namespace Jellyfin.Plugin.JellySecurity.Core.Captcha;

public enum CaptchaCheck
{
    Absent = 0,
    Passed = 1,
    Rejected = 2,
    Unreachable = 3
}
