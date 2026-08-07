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
    Task<IReadOnlyCollection<AdvisorRecommendation>> RetrieveAdvisorRecommendations(bool includeDebugOutput, Guid subscriptionId);
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

            if (content?.Value is { Length: > 0 })
            {
                networkSecurityGroups.AddRange(content.Value);
            }

            // Follow the nextLink for paged results
            if (string.IsNullOrEmpty(content?.NextLink))
            {
                break;
            }

            uri = new Uri(content.NextLink, UriKind.Absolute);
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

    public async Task<IReadOnlyCollection<AdvisorRecommendation>> RetrieveAdvisorRecommendations(bool includeDebugOutput, Guid subscriptionId)
    {
        var recommendations = new List<AdvisorRecommendation>();

        var uri = new Uri(
            $"/subscriptions/{subscriptionId}/providers/Microsoft.Advisor/recommendations?api-version=2023-01-01",
            UriKind.Relative);

        while (true)
        {
            var content = await ExecuteTypedCallToManagementApi<AdvisorRecommendationListResult>(includeDebugOutput, null, uri);

            if (content?.Value is { Length: > 0 })
            {
                recommendations.AddRange(content.Value);
            }

            // Follow the nextLink for paged results
            if (string.IsNullOrEmpty(content?.NextLink))
            {
                break;
            }

            uri = new Uri(content.NextLink, UriKind.Absolute);
        }

        if (includeDebugOutput)
        {
            var json = JsonSerializer.Serialize(recommendations, jsonSerializerOptions);
            AnsiConsole.WriteLine($"Retrieved {recommendations.Count} advisor recommendations:");
            AnsiConsole.Write(new JsonText(json));
            AnsiConsole.WriteLine();
        }

        return recommendations;
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
    string Id,
    string AuthorizationSource,
    object[] ManagedByTenants,
    string SubscriptionId,
    string TenantId,
    string DisplayName,
    string State
);

public record NetworkSecurityGroupListResult(
    NetworkSecurityGroup[] Value,
    string? NextLink
);

public record NetworkSecurityGroup(
    string Id,
    string Name,
    string Type,
    string Location,
    string? Etag,
    Dictionary<string, string>? Tags,
    NetworkSecurityGroupProperties Properties
);

public record NetworkSecurityGroupProperties(
    string ProvisioningState,
    string ResourceGuid,
    SecurityRule[]? SecurityRules,
    SecurityRule[]? DefaultSecurityRules,
    ResourceReference[]? NetworkInterfaces,
    ResourceReference[]? Subnets,
    bool? FlushConnection
);

public record SecurityRule(
    string Id,
    string Name,
    string? Etag,
    string? Type,
    SecurityRuleProperties Properties
);

public record SecurityRuleProperties(
    string? ProvisioningState,
    string? Description,
    string Protocol,
    string? SourcePortRange,
    string? DestinationPortRange,
    string? SourceAddressPrefix,
    string? DestinationAddressPrefix,
    string Access,
    int Priority,
    string Direction,
    string[]? SourcePortRanges,
    string[]? DestinationPortRanges,
    string[]? SourceAddressPrefixes,
    string[]? DestinationAddressPrefixes
);

public record ResourceReference(string Id);

public record AdvisorRecommendationListResult(
    AdvisorRecommendation[] Value,
    string? NextLink
);

public record AdvisorRecommendation(
    string Id,
    string Name,
    string Type,
    AdvisorRecommendationProperties Properties
);

public record AdvisorRecommendationProperties(
    string Category,
    string Impact,
    string? ImpactedField,
    string? ImpactedValue,
    DateTimeOffset? LastUpdated,
    string? RecommendationTypeId,
    AdvisorShortDescription? ShortDescription,
    AdvisorResourceMetadata? ResourceMetadata,
    string[]? SuppressionIds
);

public record AdvisorShortDescription(
    string? Problem,
    string? Solution
);

public record AdvisorResourceMetadata(
    string? ResourceId,
    string? Source
);
