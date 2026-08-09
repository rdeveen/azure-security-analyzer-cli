using AzureSecurityAnalyzer.ManagementApi;
using AzureSecurityAnalyzer.OutputFormatters;

using Shouldly;

namespace AzureSecurityAnalyzer.Tests.OutputFormatters;

[Collection("ConsoleOutput")]
public class MarkdownOutputFormatterTests
{
    private readonly MarkdownOutputFormatter formatter = new();

    [Fact]
    public async Task WriteNetworkSecurityGroups_WithEmptyCollection_WritesMessageWithoutHeaders()
    {
        // Act
        var output = await CaptureConsoleOutput(() => formatter.WriteNetworkSecurityGroups(
            new AzureSecurityAnalyzer.Commands.NetworkSecurityGroups.Settings(), [], []));

        // Assert
        output.ShouldContain("No network security groups found.");
        output.ShouldNotContain("# Network Security Groups");
        output.ShouldNotContain("|Name|");
    }

    [Fact]
    public async Task WriteNetworkSecurityGroups_WithNetworkSecurityGroups_WritesHeaders()
    {
        // Act
        var output = await CaptureConsoleOutput(() => formatter.WriteNetworkSecurityGroups(
            new AzureSecurityAnalyzer.Commands.NetworkSecurityGroups.Settings(), [CreateNetworkSecurityGroup()], []));

        // Assert
        output.ShouldContain("# Network Security Groups");
        output.ShouldContain("nsg1");
        output.ShouldNotContain("No network security groups found.");
    }

    [Fact]
    public async Task WriteAdvisorRecommendations_WithEmptyCollection_WritesMessageWithoutHeaders()
    {
        // Act
        var output = await CaptureConsoleOutput(() => formatter.WriteAdvisorRecommendations(
            new AzureSecurityAnalyzer.Commands.AdvisorRecommendations.Settings(), []));

        // Assert
        output.ShouldContain("No recommendations found.");
        output.ShouldNotContain("# Advisor Recommendations");
        output.ShouldNotContain("|Category|");
    }

    [Fact]
    public async Task WriteAdvisorRecommendations_WithRecommendations_WritesHeaders()
    {
        // Act
        var output = await CaptureConsoleOutput(() => formatter.WriteAdvisorRecommendations(
            new AzureSecurityAnalyzer.Commands.AdvisorRecommendations.Settings(), [CreateRecommendation()]));

        // Assert
        output.ShouldContain("# Advisor Recommendations");
        output.ShouldContain("mystorageaccount");
        output.ShouldNotContain("No recommendations found.");
    }

    private static async Task<string> CaptureConsoleOutput(Func<Task> action)
    {
        var originalOut = Console.Out;
        using var writer = new StringWriter();
        Console.SetOut(writer);

        try
        {
            await action();
        }
        finally
        {
            Console.SetOut(originalOut);
        }

        return writer.ToString();
    }

    internal static NetworkSecurityGroup CreateNetworkSecurityGroup() => new(
        Id: "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg1/providers/Microsoft.Network/networkSecurityGroups/nsg1",
        Name: "nsg1",
        Type: "Microsoft.Network/networkSecurityGroups",
        Location: "westeurope",
        Tags: null,
        Properties: new NetworkSecurityGroupProperties(
            ProvisioningState: "Succeeded",
            ResourceGuid: "00000000-0000-0000-0000-000000000001",
            SecurityRules: null,
            DefaultSecurityRules: null,
            NetworkInterfaces: null,
            Subnets: null));

    internal static AdvisorRecommendation CreateRecommendation() => new(
        Id: "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg1/providers/Microsoft.Advisor/recommendations/rec1",
        Name: "rec1",
        Type: "Microsoft.Advisor/recommendations",
        Properties: new AdvisorRecommendationProperties(
            Category: "Security",
            Impact: "High",
            ImpactedField: "Microsoft.Storage/storageAccounts",
            ImpactedValue: "mystorageaccount",
            LastUpdated: new DateTimeOffset(2026, 8, 1, 0, 0, 0, TimeSpan.Zero),
            RecommendationTypeId: "00000000-0000-0000-0000-000000000001",
            ShortDescription: new AdvisorShortDescription(
                Problem: "Storage account should use secure transfer",
                Solution: "Enable secure transfer required"),
            ResourceMetadata: null,
            SuppressionIds: null));
}
