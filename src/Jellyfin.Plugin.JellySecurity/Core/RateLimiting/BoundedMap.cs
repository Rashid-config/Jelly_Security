using System.Collections.Concurrent;
using System.Collections.Generic;

namespace Jellyfin.Plugin.JellySecurity.Core.RateLimiting;

/// <summary>
/// Caps unique attack keys so a flood cannot grow memory without limit.
/// Eviction is FIFO (first-in-first-out) so an attacker flooding random keys
/// cannot evict recently-active tracking entries for legitimate addresses.
/// All mutation (insert + evict) is serialized under a lock so two threads
/// racing through GetOrAdd cannot both enqueue the same key or evict while
/// the other is mid-insert.
/// </summary>
public sealed class BoundedMap<TValue>
{
    private readonly ConcurrentDictionary<string, TValue> _items;
    private readonly ConcurrentQueue<string> _insertionOrder;
    private readonly int _capacity;
    private readonly object _gate = new();

    public BoundedMap(int capacity, IEqualityComparer<string>? comparer = null)
    {
        _capacity = Math.Max(16, capacity);
        _items = new ConcurrentDictionary<string, TValue>(comparer ?? StringComparer.OrdinalIgnoreCase);
        _insertionOrder = new ConcurrentQueue<string>();
    }

    public int Count => _items.Count;

    public TValue GetOrAdd(string key, Func<string, TValue> factory)
    {
        if (_items.TryGetValue(key, out var existing))
        {
            return existing;
        }

        lock (_gate)
        {
            // Double-check inside the lock: another thread may have inserted
            // while we were waiting.
            if (_items.TryGetValue(key, out existing))
            {
                return existing;
            }

            EvictIfFull();
            var value = factory(key);
            _items.TryAdd(key, value);
            _insertionOrder.Enqueue(key);
            return value;
        }
    }

    public bool TryGetValue(string key, out TValue value)
    {
        return _items.TryGetValue(key, out value!);
    }

    public IReadOnlyList<KeyValuePair<string, TValue>> Snapshot()
    {
        return _items.ToArray();
    }

    private void EvictIfFull()
    {
        if (_items.Count < _capacity)
        {
            return;
        }

        var toRemove = Math.Max(1, _capacity / 20);
        for (var i = 0; i < toRemove; i++)
        {
            if (!_insertionOrder.TryDequeue(out var stale))
            {
                break;
            }

            _items.TryRemove(stale, out _);
        }
    }
}
