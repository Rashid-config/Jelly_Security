namespace Jellyfin.Plugin.JellySecurity.Core.Captcha;

public sealed record CaptchaDecision(bool ChallengeWeb, bool Block, string Reason);
