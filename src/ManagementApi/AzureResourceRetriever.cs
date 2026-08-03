using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Azure.Core;
using Azure.Identity;
using Spectre.Console;
using Spectre.Console.Json;

namespace AzureSecurityAnalyzer.ManagementApi;

public interface IAzureResourceRetriever
{
    Task<Subscription> RetrieveSubscription(bool includeDebugOutput, Guid subscriptionId);
}

public class AzureResourceRetriever(HttpClient httpClient) : IAzureResourceRetriever
{
    private readonly HttpClient _httpClient = httpClient;
    private bool _tokenRetrieved;
    public string ManagementApiAddress { get; set; }
    public TimeSpan HttpTimeout { get; set; } = TimeSpan.FromSeconds(100); // same as the .net core default

    public async Task<Subscription> RetrieveSubscription(bool includeDebugOutput, Guid subscriptionId)
    {
        var uri = new Uri(
            $"/subscriptions/{subscriptionId}/?api-version=2019-11-01",
            UriKind.Relative);

        var content = await ExecuteTypedCallToManagementApi<Subscription>(includeDebugOutput, null, uri);

        if (includeDebugOutput)
        {
            var json = JsonSerializer.Serialize(content, new JsonSerializerOptions { WriteIndented = true });
            AnsiConsole.WriteLine("Retrieved subscription details:");
            AnsiConsole.Write(new JsonText(json));
            AnsiConsole.WriteLine();
        }

        return content;
    }

    private async Task<T?> ExecuteTypedCallToManagementApi<T>(bool includeDebugOutput, object? payload, Uri uri)
        where T : class
    {
        var response = await ExecuteCallToManagementApi(includeDebugOutput, payload, uri);

        var content = await response.Content.ReadFromJsonAsync<T>();
        return content;
    }

    private async Task<HttpResponseMessage> ExecuteCallToManagementApi(bool includeDebugOutput, object? payload, Uri uri)
    {
        await RetrieveToken(includeDebugOutput);

        if (includeDebugOutput)
        {
            AnsiConsole.WriteLine($"Retrieving data from {uri} using the following payload:");
            AnsiConsole.Write(new JsonText(JsonSerializer.Serialize(payload)));
            AnsiConsole.WriteLine();
        }

        if (!string.Equals(_httpClient.BaseAddress?.ToString(), ManagementApiAddress))
        {
            _httpClient.BaseAddress = new Uri(ManagementApiAddress);
        }

        if (_httpClient.Timeout != HttpTimeout)
        {
            _httpClient.Timeout = HttpTimeout;
        }

        var options = new JsonSerializerOptions
        {
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        };

        var response = payload == null
            ? await _httpClient.GetAsync(uri)
            : await _httpClient.PostAsJsonAsync(uri, payload, options);

        if (includeDebugOutput)
        {
            AnsiConsole.WriteLine(
                $"Response status code is {response.StatusCode} and got payload size of {response.Content.Headers.ContentLength}");
            if (!response.IsSuccessStatusCode)
            {
                AnsiConsole.WriteLine($"Response content: {await response.Content.ReadAsStringAsync()}");
            }
        }

        response.EnsureSuccessStatusCode();
        return response;
    }

    private async Task RetrieveToken(bool includeDebugOutput)
    {
        if (_tokenRetrieved)
            return;

        // Get the token by using the DefaultAzureCredential, but try the AzureCliCredential first
        var tokenCredential = new ChainedTokenCredential(
            new AzureCliCredential(),
            new DefaultAzureCredential());

        if (includeDebugOutput)
            AnsiConsole.WriteLine($"Using token credential: {tokenCredential.GetType().Name} to fetch a token.");

        var token = await tokenCredential.GetTokenAsync(new TokenRequestContext(new[]
            { $"{ManagementApiAddress}.default" }));

        if (includeDebugOutput)
            AnsiConsole.WriteLine($"Token retrieved and expires at: {token.ExpiresOn}");

        // Set as the bearer token for the HTTP client
        _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token.Token);

        _tokenRetrieved = true;
    }
}

public record Subscription(
    string id,
    string authorizationSource,
    object[] managedByTenants,
    string subscriptionId,
    string tenantId,
    string displayName,
    string state
);
