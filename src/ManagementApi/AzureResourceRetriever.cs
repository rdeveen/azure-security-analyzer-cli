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
    string ManagementApiAddress { get; set; }
    TimeSpan HttpTimeout { get; set; }

    Task<Subscription> RetrieveSubscription(bool includeDebugOutput, Guid subscriptionId);
    Task<IReadOnlyCollection<NetworkSecurityGroup>> RetrieveNetworkSecurityGroups(bool includeDebugOutput, Guid subscriptionId);
}

public class AzureResourceRetriever(HttpClient httpClient) : IAzureResourceRetriever
{
    private readonly HttpClient httpClient = httpClient;
    private bool tokenRetrieved;
    public required string ManagementApiAddress { get; set; }
    public TimeSpan HttpTimeout { get; set; } = TimeSpan.FromSeconds(100); // same as the .net core default
    private readonly JsonSerializerOptions jsonSerializerOptions = new() { WriteIndented = true };

    public async Task<Subscription> RetrieveSubscription(bool includeDebugOutput, Guid subscriptionId)
    {
        var uri = new Uri(
            $"/subscriptions/{subscriptionId}/?api-version=2019-11-01",
            UriKind.Relative);

        var content = await ExecuteTypedCallToManagementApi<Subscription>(includeDebugOutput, null, uri);

        if (includeDebugOutput)
        {
            var json = JsonSerializer.Serialize(content, jsonSerializerOptions);
            AnsiConsole.WriteLine("Retrieved subscription details:");
            AnsiConsole.Write(new JsonText(json));
            AnsiConsole.WriteLine();
        }

        return content;
    }

    public async Task<IReadOnlyCollection<NetworkSecurityGroup>> RetrieveNetworkSecurityGroups(bool includeDebugOutput, Guid subscriptionId)
    {
        var networkSecurityGroups = new List<NetworkSecurityGroup>();

        var uri = new Uri(
            $"/subscriptions/{subscriptionId}/providers/Microsoft.Network/networkSecurityGroups?api-version=2024-05-01",
            UriKind.Relative);

        while (true)
        {
            var content = await ExecuteTypedCallToManagementApi<NetworkSecurityGroupListResult>(includeDebugOutput, null, uri);

            if (content?.value is { Length: > 0 })
            {
                networkSecurityGroups.AddRange(content.value);
            }

            // Follow the nextLink for paged results
            if (string.IsNullOrEmpty(content?.nextLink))
            {
                break;
            }

            uri = new Uri(content.nextLink, UriKind.Absolute);
        }

        if (includeDebugOutput)
        {
            var json = JsonSerializer.Serialize(networkSecurityGroups, jsonSerializerOptions);
            AnsiConsole.WriteLine($"Retrieved {networkSecurityGroups.Count} network security groups:");
            AnsiConsole.Write(new JsonText(json));
            AnsiConsole.WriteLine();
        }

        return networkSecurityGroups;
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
            AnsiConsole.Write(new JsonText(JsonSerializer.Serialize(payload, jsonSerializerOptions)));
            AnsiConsole.WriteLine();
        }

        if (!string.Equals(httpClient.BaseAddress?.ToString(), ManagementApiAddress))
        {
            httpClient.BaseAddress = new Uri(ManagementApiAddress);
        }

        if (httpClient.Timeout != HttpTimeout)
        {
            httpClient.Timeout = HttpTimeout;
        }

        var options = new JsonSerializerOptions
        {
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        };

        var response = payload == null
            ? await httpClient.GetAsync(uri)
            : await httpClient.PostAsJsonAsync(uri, payload, options);

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
        if (tokenRetrieved)
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
        httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token.Token);

        tokenRetrieved = true;
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

public record NetworkSecurityGroupListResult(
    NetworkSecurityGroup[] value,
    string? nextLink
);

public record NetworkSecurityGroup(
    string id,
    string name,
    string type,
    string location,
    string? etag,
    Dictionary<string, string>? tags,
    NetworkSecurityGroupProperties properties
);

public record NetworkSecurityGroupProperties(
    string provisioningState,
    string resourceGuid,
    SecurityRule[]? securityRules,
    SecurityRule[]? defaultSecurityRules,
    ResourceReference[]? networkInterfaces,
    ResourceReference[]? subnets,
    bool? flushConnection
);

public record SecurityRule(
    string id,
    string name,
    string? etag,
    string? type,
    SecurityRuleProperties properties
);

public record SecurityRuleProperties(
    string? provisioningState,
    string? description,
    string protocol,
    string? sourcePortRange,
    string? destinationPortRange,
    string? sourceAddressPrefix,
    string? destinationAddressPrefix,
    string access,
    int priority,
    string direction,
    string[]? sourcePortRanges,
    string[]? destinationPortRanges,
    string[]? sourceAddressPrefixes,
    string[]? destinationAddressPrefixes
);

public record ResourceReference(string id);
