using Jellyfin.Plugin.JellySecurity.Core.Engine;
using Xunit;

namespace Jellyfin.Plugin.JellySecurity.Tests;

public class SecurityEventHubTests
{
    [Fact]
    public async Task Publish_DeliversToSubscriber()
    {
        var hub = new SecurityEventHub();
        using var cts = new CancellationTokenSource();
        cts.CancelAfter(TimeSpan.FromSeconds(5));

        // Subscribe first, then publish.
        var subscribeTask = Task.Run(async () =>
        {
            await foreach (var n in hub.Subscribe(cts.Token))
            {
                Assert.Equal("event", n.Type);
                Assert.Equal("test event", n.Summary);
                break;
            }
        });

        await Task.Delay(50); // let the subscription register
        hub.Publish(new LiveNotification { Type = "event", Summary = "test event" });

        await subscribeTask;
        hub.Dispose();
    }

    [Fact]
    public void Publish_WithNoSubscribers_DoesNotThrow()
    {
        var hub = new SecurityEventHub();
        hub.Publish(new LiveNotification { Type = "event", Summary = "no one listening" });
        hub.Dispose();
    }

    [Fact]
    public async Task MultipleSubscribers_AllReceiveNotifications()
    {
        var hub = new SecurityEventHub();
        using var cts = new CancellationTokenSource();
        cts.CancelAfter(TimeSpan.FromSeconds(5));

        var received1 = new List<LiveNotification>();
        var received2 = new List<LiveNotification>();
        var sub1 = Task.Run(async () =>
        {
            await foreach (var n in hub.Subscribe(cts.Token))
            {
                received1.Add(n);
                if (received1.Count >= 1) break;
            }
        });
        var sub2 = Task.Run(async () =>
        {
            await foreach (var n in hub.Subscribe(cts.Token))
            {
                received2.Add(n);
                if (received2.Count >= 1) break;
            }
        });

        await Task.Delay(50); // let both subscriptions register
        hub.Publish(new LiveNotification { Type = "ban", Summary = "ban added" });

        await Task.WhenAll(sub1, sub2);

        Assert.Single(received1);
        Assert.Equal("ban", received1[0].Type);
        Assert.Single(received2);
        Assert.Equal("ban", received2[0].Type);

        hub.Dispose();
    }

    [Fact]
    public async Task Notification_HasTimestamp()
    {
        var hub = new SecurityEventHub();
        using var cts = new CancellationTokenSource();
        cts.CancelAfter(TimeSpan.FromSeconds(5));

        var before = DateTimeOffset.UtcNow;
        LiveNotification? received = null;
        var sub = Task.Run(async () =>
        {
            await foreach (var n in hub.Subscribe(cts.Token))
            {
                received = n;
                break;
            }
        });

        await Task.Delay(50);
        hub.Publish(new LiveNotification { Type = "event", Summary = "ts test" });

        await sub;
        Assert.NotNull(received);
        Assert.True(received!.TimestampUtc >= before.AddSeconds(-1));

        hub.Dispose();
    }

    [Fact]
    public async Task RapidPublishes_AllDelivered()
    {
        var hub = new SecurityEventHub();
        using var cts = new CancellationTokenSource();
        cts.CancelAfter(TimeSpan.FromSeconds(5));

        var received = new List<string>();
        var sub = Task.Run(async () =>
        {
            await foreach (var n in hub.Subscribe(cts.Token))
            {
                received.Add(n.Summary);
                if (received.Count >= 3) break;
            }
        });

        await Task.Delay(50);
        hub.Publish(new LiveNotification { Type = "event", Summary = "first" });
        hub.Publish(new LiveNotification { Type = "ban", Summary = "second" });
        hub.Publish(new LiveNotification { Type = "event", Summary = "third" });

        await sub;
        Assert.Equal(new[] { "first", "second", "third" }, received);

        hub.Dispose();
    }
}
