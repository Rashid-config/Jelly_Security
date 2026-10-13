using Jellyfin.Plugin.JellySecurity.Core.Captcha;
using Jellyfin.Plugin.JellySecurity.Core.Engine;
using Jellyfin.Plugin.JellySecurity.Core.Networking;
using Jellyfin.Plugin.JellySecurity.Integration;
using Jellyfin.Plugin.JellySecurity.Storage;
using MediaBrowser.Controller;
using MediaBrowser.Controller.Plugins;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;

namespace Jellyfin.Plugin.JellySecurity;

/// <summary>
/// Registers engine services. Requires a parameterless constructor.
/// </summary>
public class PluginServiceRegistrator : IPluginServiceRegistrator
{
    /// <inheritdoc />
    public void RegisterServices(IServiceCollection serviceCollection, IServerApplicationHost applicationHost)
    {
        serviceCollection.AddSingleton<SecurityStore>();
        serviceCollection.AddSingleton<ProxyTrustValidator>();
        serviceCollection.AddSingleton<CaptchaVerifier>();
        serviceCollection.AddSingleton<SecurityEventHub>();
        serviceCollection.AddSingleton<SecurityEngine>();
        serviceCollection.AddSingleton<IStartupFilter, AuthGuardStartupFilter>();
        serviceCollection.AddHostedService<PluginFlushService>();
    }
}
