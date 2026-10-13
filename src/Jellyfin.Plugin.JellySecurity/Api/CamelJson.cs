using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Jellyfin.Plugin.JellySecurity.Api;

/// <summary>
/// Writes dashboard JSON with the camelCase names the configuration page reads.
/// The host serializer keeps the declared C# names, so PascalCase members never reached the page.
/// </summary>
public static class CamelJson
{
    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DictionaryKeyPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new JsonStringEnumConverter() }
    };

    public static string Serialize(object value) => JsonSerializer.Serialize(value, Options);

    public static ContentResult Ok(object value) => Json(value, StatusCodes.Status200OK);

    private static ContentResult Json(object value, int statusCode) =>
        new()
        {
            Content = Serialize(value),
            ContentType = "application/json; charset=utf-8",
            StatusCode = statusCode
        };
}
