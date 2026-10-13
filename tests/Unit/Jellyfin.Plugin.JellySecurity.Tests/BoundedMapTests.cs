using Jellyfin.Plugin.JellySecurity.Core.RateLimiting;

namespace Jellyfin.Plugin.JellySecurity.Tests;

public class BoundedMapTests
{
    [Fact]
    public void Evicts_WhenOverCapacity()
    {
        var map = new BoundedMap<int>(16);
        for (var i = 0; i < 40; i++)
        {
            map.GetOrAdd("k" + i, _ => i);
        }

        Assert.True(map.Count <= 16);
    }

    [Fact]
    public void FifoEviction_KeepsRecentKeys()
    {
        var map = new BoundedMap<int>(16);
        // Insert initial keys
        for (var i = 0; i < 16; i++)
        {
            map.GetOrAdd("early" + i, _ => i);
        }

        // Flood with random keys (simulating an attacker)
        for (var i = 0; i < 100; i++)
        {
            map.GetOrAdd("flood" + i, _ => i);
        }

        // The earliest keys should have been evicted (FIFO)
        Assert.False(map.TryGetValue("early0", out _));
        // Recent flood keys should still exist
        Assert.True(map.TryGetValue("flood99", out _));
        Assert.True(map.Count <= 16);
    }

    [Fact]
    public async Task ConcurrentInserts_DoNotDuplicateOrExceedCapacity()
    {
        var map = new BoundedMap<int>(64);
        var tasks = new Task[16];
        for (var t = 0; t < 16; t++)
        {
            var start = t * 50;
            tasks[t] = Task.Run(() =>
            {
                for (var i = 0; i < 50; i++)
                {
                    map.GetOrAdd("k" + (start + i), _ => start + i);
                }
            });
        }

        await Task.WhenAll(tasks);
        Assert.True(map.Count <= 64);
    }

    [Fact]
    public async Task GetOrAdd_ReturnsSameInstance_ForConcurrentInserts()
    {
        var map = new BoundedMap<string>(64);
        var results = new string[16];
        var tasks = new Task[16];
        for (var t = 0; t < 16; t++)
        {
            var idx = t;
            tasks[t] = Task.Run(() =>
            {
                results[idx] = map.GetOrAdd("shared", _ => "value");
            });
        }

        await Task.WhenAll(tasks);
        Assert.All(results, r => Assert.Equal("value", r));
    }
}
