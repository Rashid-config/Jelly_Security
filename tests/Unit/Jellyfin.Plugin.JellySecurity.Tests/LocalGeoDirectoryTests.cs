using Jellyfin.Plugin.JellySecurity.Core.Geo;

namespace Jellyfin.Plugin.JellySecurity.Tests;

public class LocalGeoDirectoryTests
{
    [Fact]
    public void Matches_Cidr_AndIgnoresComments()
    {
        var path = Path.Combine(Path.GetTempPath(), "jelly-geo-" + Guid.NewGuid().ToString("N") + ".csv");
        File.WriteAllText(path, "# comment\n203.0.113.0/24,US,AS64496\n");
        try
        {
            var records = LocalGeoDirectory.Load(path);
            var hit = LocalGeoDirectory.Lookup("203.0.113.40", records);
            Assert.Equal("US", hit?.Country);
            Assert.Null(LocalGeoDirectory.Lookup("198.51.100.1", records));
        }
        finally
        {
            File.Delete(path);
        }
    }
}
