using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;

namespace Jellyfin.Plugin.JellySecurity.Integration;

public sealed class AuthGuardStartupFilter : IStartupFilter
{
    public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next)
    {
        return app =>
        {
            app.UseMiddleware<CaptchaPageMiddleware>();
            app.UseMiddleware<AuthGuardMiddleware>();
            next(app);
        };
    }
}
