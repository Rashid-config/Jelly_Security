using Jellyfin.Plugin.JellySecurity.Integration;
using Microsoft.AspNetCore.Http;

namespace Jellyfin.Plugin.JellySecurity.Tests;

public class AuthPathClassifierTests
{
    [Theory]
    [InlineData("/Users/AuthenticateByName", "POST", AuthPathKind.Password)]
    [InlineData("/Users/AuthenticateWithQuickConnect", "POST", AuthPathKind.QuickConnect)]
    [InlineData("/Users/8b4e2c1a-6d3f-4a19-9e2b-7c5f1d8a0b34/Authenticate", "POST", AuthPathKind.Password)]
    [InlineData("/Users/ForgotPassword", "POST", AuthPathKind.PasswordReset)]
    [InlineData("/QuickConnect/Initiate", "POST", AuthPathKind.QuickConnect)]
    [InlineData("/Videos/123/stream", "GET", AuthPathKind.None)]
    [InlineData("/Users/AuthenticateByName", "GET", AuthPathKind.None)]
    [InlineData("/Users", "POST", AuthPathKind.Admin)]
    [InlineData("/Users/8b4e2c1a-6d3f-4a19-9e2b-7c5f1d8a0b34/Policy", "POST", AuthPathKind.Admin)]
    [InlineData("/System/Configuration", "POST", AuthPathKind.Admin)]
    [InlineData("/Sessions", "GET", AuthPathKind.Session)]
    [InlineData("/Sessions/abc/Playing", "POST", AuthPathKind.None)]
    [InlineData("/Startup/Configuration", "POST", AuthPathKind.None)]
    [InlineData("/Startup/Complete", "POST", AuthPathKind.None)]
    [InlineData("/foo/Users/AuthenticateByName", "POST", AuthPathKind.None)]
    [InlineData("/bar/Users/ForgotPassword", "POST", AuthPathKind.None)]
    public void Classifies_Jellyfin12Routes(string path, string method, AuthPathKind expected)
    {
        var context = new DefaultHttpContext();
        context.Request.Path = path;
        context.Request.Method = method;
        Assert.Equal(expected, AuthPathClassifier.Classify(context.Request));
    }

    [Theory]
    [InlineData("/Users/AuthenticateByName")]
    [InlineData("/Users/8b4e2c1a-6d3f-4a19-9e2b-7c5f1d8a0b34/Authenticate")]
    [InlineData("/Users/AuthenticateWithQuickConnect")]
    [InlineData("/QuickConnect/Initiate")]
    [InlineData("/QuickConnect/Authorize")]
    [InlineData("/Users/ForgotPassword")]
    public void CredentialPaths_FeedTheFailureCounter(string path)
    {
        Assert.True(AuthPathClassifier.IsCredentialPath(path));
    }

    [Theory]
    [InlineData("/Sessions")]
    [InlineData("/Sessions/abc")]
    [InlineData("/System/Configuration")]
    [InlineData("/Users/8b4e2c1a-6d3f-4a19-9e2b-7c5f1d8a0b34/Policy")]
    [InlineData("/Items")]
    [InlineData("/foo/Users/AuthenticateByName")]
    [InlineData("")]
    public void NonCredentialPaths_DoNotFeedTheFailureCounter(string path)
    {
        Assert.False(AuthPathClassifier.IsCredentialPath(path));
    }
}
