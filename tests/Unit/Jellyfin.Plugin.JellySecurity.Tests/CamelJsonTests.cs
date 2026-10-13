using System.Text.Json;
using Jellyfin.Plugin.JellySecurity.Api;
using Jellyfin.Plugin.JellySecurity.Core.Reports;
using Jellyfin.Plugin.JellySecurity.Core.Sessions;

namespace Jellyfin.Plugin.JellySecurity.Tests;

public class CamelJsonTests
{
    [Fact]
    public void DashboardPayload_UsesCamelCaseNamesThePageReads()
    {
        var report = new SecurityReport(
            24,
            3,
            1,
            1,
            1,
            0,
            0,
            2.5,
            ["Observe:1"],
            ["Counts come from plugin events."]);
        using var reportDoc = JsonDocument.Parse(CamelJson.Serialize(report));
        Assert.Equal(3, reportDoc.RootElement.GetProperty("events").GetInt32());
        Assert.Equal(1, reportDoc.RootElement.GetProperty("failed").GetInt32());
        Assert.Equal(2.5, reportDoc.RootElement.GetProperty("averageRiskScore").GetDouble());
        Assert.Equal("Counts come from plugin events.", reportDoc.RootElement.GetProperty("dataQuality")[0].GetString());
        Assert.False(reportDoc.RootElement.TryGetProperty("Events", out _));

        var status = new
        {
            mode = "Balanced",
            EngineState = "MonitorOnly",
            ProxyStatus = "Verified",
            EventsLast24Hours = 27,
            Warnings = new[] { "A separate counter." },
            sessionWatch = new SessionWatchReport(
                [new SessionWatchRow("person", "phone", "203.0.113.8", false, "", "NewAddress")],
                1,
                1)
        };
        using var statusDoc = JsonDocument.Parse(CamelJson.Serialize(status));
        Assert.Equal("Balanced", statusDoc.RootElement.GetProperty("mode").GetString());
        Assert.Equal("MonitorOnly", statusDoc.RootElement.GetProperty("engineState").GetString());
        Assert.Equal("Verified", statusDoc.RootElement.GetProperty("proxyStatus").GetString());
        Assert.Equal(27, statusDoc.RootElement.GetProperty("eventsLast24Hours").GetInt32());
        Assert.Equal("A separate counter.", statusDoc.RootElement.GetProperty("warnings")[0].GetString());
        var sessions = statusDoc.RootElement.GetProperty("sessionWatch").GetProperty("sessions");
        Assert.Equal(1, sessions.GetArrayLength());
        Assert.Equal("NewAddress", sessions[0].GetProperty("reason").GetString());
        Assert.False(statusDoc.RootElement.TryGetProperty("EngineState", out _));
        Assert.False(statusDoc.RootElement.TryGetProperty("EventsLast24Hours", out _));
    }
}
