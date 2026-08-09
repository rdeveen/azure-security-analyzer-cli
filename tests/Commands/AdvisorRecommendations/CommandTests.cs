using AzureSecurityAnalyzer.Commands.AdvisorRecommendations;
using Command = AzureSecurityAnalyzer.Commands.AdvisorRecommendations.Command;
using AzureSecurityAnalyzer.ManagementApi;
using AzureSecurityAnalyzer.OutputFormatters;

using Shouldly;
using Moq;
using Spectre.Console.Cli;
using AzureSecurityAnalyzer.Commands;

namespace AzureSecurityAnalyzer.Tests.Commands.AdvisorRecommendations;

public class CommandTests
{
    private readonly Mock<IAzureResourceRetriever> mockAzureResourceRetriever;
    private readonly Command command;

    public CommandTests()
    {
        mockAzureResourceRetriever = new Mock<IAzureResourceRetriever>(MockBehavior.Strict);
        mockAzureResourceRetriever.SetupAllProperties();
        command = new Command(mockAzureResourceRetriever.Object);
    }

    [Fact]
    public void Constructor_SetsUpOutputFormatters()
    {
        // Act & Assert - Constructor should not throw
        var command = new Command(mockAzureResourceRetriever.Object);
        command.ShouldNotBeNull();
    }

    [Fact]
    public void AdvisorRecommendationsSettings_DefaultValues_AreSetCorrectly()
    {
        // Arrange & Act
        var settings = new Settings();

        // Assert
        settings.Output.ShouldBe(AzureSecurityAnalyzer.Commands.OutputFormat.Console);
        settings.ManagementApiAddress.ShouldBe("https://management.azure.com/");
        settings.HttpTimeout.ShouldBe(100);
    }

    [Fact]
    public void AdvisorRecommendationsSettings_WithResourceGroup_GetScopeReturnsResourceGroupScope()
    {
        // Arrange
        var subscriptionId = Guid.NewGuid();
        var settings = new Settings
        {
            Subscription = subscriptionId,
            ResourceGroup = "azure-security-analyzer-cli-rg"
        };

        // Act
        var scope = settings.GetScope;

        // Assert
        scope.Name.ShouldBe("ResourceGroup");
        scope.ScopePath.ShouldBe($"/subscriptions/{subscriptionId}/resourceGroups/azure-security-analyzer-cli-rg");
        scope.IsSubscriptionBased.ShouldBeTrue();
    }

    [Fact]
    public async Task ExecuteAsync_CallsResourceRetriever_Once()
    {
        // Arrange
        var subscriptionId = Guid.NewGuid();
        mockAzureResourceRetriever
            .Setup(r => r.RetrieveAdvisorRecommendations(It.IsAny<bool>(), subscriptionId, MatchesSubscriptionScope(subscriptionId)))
            .ReturnsAsync([CreateRecommendation()]);
        mockAzureResourceRetriever
            .Setup(r => r.RetrieveDefenderForCloudRecommendations(It.IsAny<bool>(), subscriptionId, MatchesSubscriptionScope(subscriptionId)))
            .ReturnsAsync([]);
        mockAzureResourceRetriever
            .Setup(r => r.RetrieveDefenderForCloudSecurityPolicies(It.IsAny<bool>(), subscriptionId))
            .ReturnsAsync([]);
        var settings = new Settings { Quiet = true, Subscription = subscriptionId };

        // Act
        await ExecuteAsync(settings);

        // Assert
        mockAzureResourceRetriever.Verify(r => r.RetrieveAdvisorRecommendations(It.IsAny<bool>(), subscriptionId, MatchesSubscriptionScope(subscriptionId)), Times.Once);
        mockAzureResourceRetriever.Verify(r => r.RetrieveDefenderForCloudRecommendations(It.IsAny<bool>(), subscriptionId, MatchesSubscriptionScope(subscriptionId)), Times.Once);
        mockAzureResourceRetriever.Verify(r => r.RetrieveDefenderForCloudSecurityPolicies(It.IsAny<bool>(), subscriptionId), Times.Once);
    }

    [Fact]
    public async Task ExecuteAsync_ConfiguresRetriever_FromSettings()
    {
        // Arrange
        var subscriptionId = Guid.NewGuid();
        mockAzureResourceRetriever
            .Setup(r => r.RetrieveAdvisorRecommendations(It.IsAny<bool>(), subscriptionId, MatchesSubscriptionScope(subscriptionId)))
            .ReturnsAsync([]);
        mockAzureResourceRetriever
            .Setup(r => r.RetrieveDefenderForCloudRecommendations(It.IsAny<bool>(), subscriptionId, MatchesSubscriptionScope(subscriptionId)))
            .ReturnsAsync([]);
        mockAzureResourceRetriever
            .Setup(r => r.RetrieveDefenderForCloudSecurityPolicies(It.IsAny<bool>(), subscriptionId))
            .ReturnsAsync([]);
        var settings = new Settings
        {
            Quiet = true,
            Subscription = subscriptionId,
            ManagementApiAddress = "https://management.example.com/",
            HttpTimeout = 42
        };

        // Act
        await ExecuteAsync(settings);

        // Assert
        mockAzureResourceRetriever.VerifySet(r => r.ManagementApiAddress = "https://management.example.com/", Times.Once);
        mockAzureResourceRetriever.VerifySet(r => r.HttpTimeout = TimeSpan.FromSeconds(42), Times.Once);
    }

    [Fact]
    public async Task ExecuteAsync_WithResourceGroupScope_CallsRetrieversWithResourceGroupScope()
    {
        // Arrange
        var subscriptionId = Guid.NewGuid();
        mockAzureResourceRetriever
            .Setup(r => r.RetrieveAdvisorRecommendations(It.IsAny<bool>(), subscriptionId, MatchesResourceGroupScope(subscriptionId, "azure-security-analyzer-cli-rg")))
            .ReturnsAsync([CreateRecommendation()]);
        mockAzureResourceRetriever
            .Setup(r => r.RetrieveDefenderForCloudRecommendations(It.IsAny<bool>(), subscriptionId, MatchesResourceGroupScope(subscriptionId, "azure-security-analyzer-cli-rg")))
            .ReturnsAsync([]);
        mockAzureResourceRetriever
            .Setup(r => r.RetrieveDefenderForCloudSecurityPolicies(It.IsAny<bool>(), subscriptionId))
            .ReturnsAsync([]);
        var settings = new Settings
        {
            Quiet = true,
            Subscription = subscriptionId,
            ResourceGroup = "azure-security-analyzer-cli-rg"
        };

        // Act
        var result = await ExecuteAsync(settings);

        // Assert
        result.ShouldBe(0);
        mockAzureResourceRetriever.Verify(r => r.RetrieveAdvisorRecommendations(It.IsAny<bool>(), subscriptionId, MatchesResourceGroupScope(subscriptionId, "azure-security-analyzer-cli-rg")), Times.Once);
        mockAzureResourceRetriever.Verify(r => r.RetrieveDefenderForCloudRecommendations(It.IsAny<bool>(), subscriptionId, MatchesResourceGroupScope(subscriptionId, "azure-security-analyzer-cli-rg")), Times.Once);
        mockAzureResourceRetriever.Verify(r => r.RetrieveDefenderForCloudSecurityPolicies(It.IsAny<bool>(), subscriptionId), Times.Once);
    }

    [Fact]
    public async Task ExecuteAsync_WithRecommendations_ReturnsZero()
    {
        // Arrange
        var subscriptionId = Guid.NewGuid();
        mockAzureResourceRetriever
            .Setup(r => r.RetrieveAdvisorRecommendations(It.IsAny<bool>(), subscriptionId, MatchesSubscriptionScope(subscriptionId)))
            .ReturnsAsync([CreateRecommendation(), CreateRecommendation(category: "Cost", impact: "Medium")]);
        mockAzureResourceRetriever
            .Setup(r => r.RetrieveDefenderForCloudRecommendations(It.IsAny<bool>(), subscriptionId, MatchesSubscriptionScope(subscriptionId)))
            .ReturnsAsync([]);
        mockAzureResourceRetriever
            .Setup(r => r.RetrieveDefenderForCloudSecurityPolicies(It.IsAny<bool>(), subscriptionId))
            .ReturnsAsync([]);
        var settings = new Settings { Quiet = true, Subscription = subscriptionId };

        // Act
        var result = await ExecuteAsync(settings);

        // Assert
        result.ShouldBe(0);
    }

    [Fact]
    public async Task ExecuteAsync_WithEmptyRecommendations_ReturnsZero()
    {
        // Arrange
        var subscriptionId = Guid.NewGuid();
        mockAzureResourceRetriever
            .Setup(r => r.RetrieveAdvisorRecommendations(It.IsAny<bool>(), subscriptionId, MatchesSubscriptionScope(subscriptionId)))
            .ReturnsAsync([]);
        mockAzureResourceRetriever
            .Setup(r => r.RetrieveDefenderForCloudRecommendations(It.IsAny<bool>(), subscriptionId, MatchesSubscriptionScope(subscriptionId)))
            .ReturnsAsync([]);
        mockAzureResourceRetriever
            .Setup(r => r.RetrieveDefenderForCloudSecurityPolicies(It.IsAny<bool>(), subscriptionId))
            .ReturnsAsync([]);
        var settings = new Settings { Quiet = true, Subscription = subscriptionId };

        // Act
        var result = await ExecuteAsync(settings);

        // Assert
        result.ShouldBe(0);
        mockAzureResourceRetriever.Verify(r => r.RetrieveAdvisorRecommendations(It.IsAny<bool>(), subscriptionId, MatchesSubscriptionScope(subscriptionId)), Times.Once);
        mockAzureResourceRetriever.Verify(r => r.RetrieveDefenderForCloudRecommendations(It.IsAny<bool>(), subscriptionId, MatchesSubscriptionScope(subscriptionId)), Times.Once);
        mockAzureResourceRetriever.Verify(r => r.RetrieveDefenderForCloudSecurityPolicies(It.IsAny<bool>(), subscriptionId), Times.Once);
    }

    [Theory]
    [InlineData(AzureSecurityAnalyzer.Commands.OutputFormat.Console)]
    [InlineData(AzureSecurityAnalyzer.Commands.OutputFormat.Json)]
    [InlineData(AzureSecurityAnalyzer.Commands.OutputFormat.Jsonc)]
    [InlineData(AzureSecurityAnalyzer.Commands.OutputFormat.Markdown)]
    public async Task ExecuteAsync_WithSupportedOutputFormats_ReturnsZero(AzureSecurityAnalyzer.Commands.OutputFormat outputFormat)
    {
        // Arrange
        var subscriptionId = Guid.NewGuid();
        mockAzureResourceRetriever
            .Setup(r => r.RetrieveAdvisorRecommendations(It.IsAny<bool>(), subscriptionId, MatchesSubscriptionScope(subscriptionId)))
            .ReturnsAsync([CreateRecommendation()]);
        mockAzureResourceRetriever
            .Setup(r => r.RetrieveDefenderForCloudRecommendations(It.IsAny<bool>(), subscriptionId, MatchesSubscriptionScope(subscriptionId)))
            .ReturnsAsync([]);
        mockAzureResourceRetriever
            .Setup(r => r.RetrieveDefenderForCloudSecurityPolicies(It.IsAny<bool>(), subscriptionId))
            .ReturnsAsync([CreateSecurityPricing()]);
        var settings = new Settings { Quiet = true, Subscription = subscriptionId, Output = outputFormat };

        // Act
        var result = await ExecuteAsync(settings);

        // Assert
        result.ShouldBe(0);
        mockAzureResourceRetriever.Verify(r => r.RetrieveAdvisorRecommendations(It.IsAny<bool>(), subscriptionId, MatchesSubscriptionScope(subscriptionId)), Times.Once);
        mockAzureResourceRetriever.Verify(r => r.RetrieveDefenderForCloudRecommendations(It.IsAny<bool>(), subscriptionId, MatchesSubscriptionScope(subscriptionId)), Times.Once);
        mockAzureResourceRetriever.Verify(r => r.RetrieveDefenderForCloudSecurityPolicies(It.IsAny<bool>(), subscriptionId), Times.Once);
    }

    [Fact]
    public async Task ExecuteAsync_WithNullOptionalProperties_ReturnsZero()
    {
        // Arrange - recommendation with all optional properties set to null
        var subscriptionId = Guid.NewGuid();
        var recommendation = new AdvisorRecommendation(
            Id: "/subscriptions/00000000-0000-0000-0000-000000000000/providers/Microsoft.Advisor/recommendations/rec1",
            Name: "rec1",
            Type: "Microsoft.Advisor/recommendations",
            Properties: new AdvisorRecommendationProperties(
                Category: "Security",
                Impact: "High",
                ImpactedField: null,
                ImpactedValue: null,
                LastUpdated: null,
                RecommendationTypeId: null,
                ShortDescription: null,
                ResourceMetadata: null,
                SuppressionIds: null));
        mockAzureResourceRetriever
            .Setup(r => r.RetrieveAdvisorRecommendations(It.IsAny<bool>(), subscriptionId, MatchesSubscriptionScope(subscriptionId)))
            .ReturnsAsync([recommendation]);
        mockAzureResourceRetriever
            .Setup(r => r.RetrieveDefenderForCloudRecommendations(It.IsAny<bool>(), subscriptionId, MatchesSubscriptionScope(subscriptionId)))
            .ReturnsAsync([]);
        mockAzureResourceRetriever
            .Setup(r => r.RetrieveDefenderForCloudSecurityPolicies(It.IsAny<bool>(), subscriptionId))
            .ReturnsAsync([]);
        var settings = new Settings { Quiet = true, Subscription = subscriptionId };

        // Act
        var result = await ExecuteAsync(settings);

        // Assert
        result.ShouldBe(0);
    }

    [Fact]
    public async Task ExecuteAsync_WhenRetrieverThrows_PropagatesException()
    {
        // Arrange
        var subscriptionId = Guid.NewGuid();
        mockAzureResourceRetriever
            .Setup(r => r.RetrieveAdvisorRecommendations(It.IsAny<bool>(), subscriptionId, MatchesSubscriptionScope(subscriptionId)))
            .ThrowsAsync(new HttpRequestException("API unavailable"));
        var settings = new Settings { Quiet = true, Subscription = subscriptionId };

        // Act & Assert
        var exception = await Should.ThrowAsync<HttpRequestException>(() => ExecuteAsync(settings));
        exception.Message.ShouldBe("API unavailable");
    }

    [Fact]
    public async Task ExecuteAsync_WithSecurityPolicies_CallsRetrieveDefenderForCloudSecurityPolicies()
    {
        // Arrange
        var subscriptionId = Guid.NewGuid();
        mockAzureResourceRetriever
            .Setup(r => r.RetrieveAdvisorRecommendations(It.IsAny<bool>(), subscriptionId, MatchesSubscriptionScope(subscriptionId)))
            .ReturnsAsync([]);
        mockAzureResourceRetriever
            .Setup(r => r.RetrieveDefenderForCloudRecommendations(It.IsAny<bool>(), subscriptionId, MatchesSubscriptionScope(subscriptionId)))
            .ReturnsAsync([]);
        mockAzureResourceRetriever
            .Setup(r => r.RetrieveDefenderForCloudSecurityPolicies(It.IsAny<bool>(), subscriptionId))
            .ReturnsAsync([CreateSecurityPricing(), CreateSecurityPricing(name: "StorageAccounts", pricingTier: "Free")]);
        var settings = new Settings { Quiet = true, Subscription = subscriptionId };

        // Act
        var result = await ExecuteAsync(settings);

        // Assert
        result.ShouldBe(0);
        mockAzureResourceRetriever.Verify(r => r.RetrieveDefenderForCloudSecurityPolicies(It.IsAny<bool>(), subscriptionId), Times.Once);
    }

    [Fact]
    public async Task ExecuteAsync_WithEmptySecurityPolicies_ReturnsZero()
    {
        // Arrange
        var subscriptionId = Guid.NewGuid();
        mockAzureResourceRetriever
            .Setup(r => r.RetrieveAdvisorRecommendations(It.IsAny<bool>(), subscriptionId, MatchesSubscriptionScope(subscriptionId)))
            .ReturnsAsync([]);
        mockAzureResourceRetriever
            .Setup(r => r.RetrieveDefenderForCloudRecommendations(It.IsAny<bool>(), subscriptionId, MatchesSubscriptionScope(subscriptionId)))
            .ReturnsAsync([]);
        mockAzureResourceRetriever
            .Setup(r => r.RetrieveDefenderForCloudSecurityPolicies(It.IsAny<bool>(), subscriptionId))
            .ReturnsAsync([]);
        var settings = new Settings { Quiet = true, Subscription = subscriptionId };

        // Act
        var result = await ExecuteAsync(settings);

        // Assert
        result.ShouldBe(0);
        mockAzureResourceRetriever.Verify(r => r.RetrieveDefenderForCloudSecurityPolicies(It.IsAny<bool>(), subscriptionId), Times.Once);
    }

    [Theory]
    [InlineData("High", 0)]
    [InlineData("Medium", 1)]
    [InlineData("Low", 2)]
    [InlineData("Unknown", 3)]
    public void GetImpactOrder_ReturnsExpectedOrder(string impact, int expectedOrder)
    {
        // Arrange
        var recommendation = CreateRecommendation(impact: impact);

        // Act & Assert
        recommendation.GetImpactOrder().ShouldBe(expectedOrder);
    }

    private Task<int> ExecuteAsync(Settings settings)
    {
        return ((ICommand<Settings>)command).ExecuteAsync(CreateCommandContext(), settings, CancellationToken.None);
    }

    private static Scope MatchesSubscriptionScope(Guid subscriptionId) => It.Is<Scope>(scope =>
        scope.Name == "Subscription"
        && scope.ScopePath == $"/subscriptions/{subscriptionId}"
        && scope.IsSubscriptionBased);

    private static Scope MatchesResourceGroupScope(Guid subscriptionId, string resourceGroup) => It.Is<Scope>(scope =>
        scope.Name == "ResourceGroup"
        && scope.ScopePath == $"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroup}"
        && scope.IsSubscriptionBased);

    private static AdvisorRecommendation CreateRecommendation(string category = "Security", string impact = "High") => new(
        Id: "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg1/providers/Microsoft.Advisor/recommendations/rec1",
        Name: "rec1",
        Type: "Microsoft.Advisor/recommendations",
        Properties: new AdvisorRecommendationProperties(
            Category: category,
            Impact: impact,
            ImpactedField: "Microsoft.Storage/storageAccounts",
            ImpactedValue: "mystorageaccount",
            LastUpdated: new DateTimeOffset(2026, 8, 1, 0, 0, 0, TimeSpan.Zero),
            RecommendationTypeId: "00000000-0000-0000-0000-000000000001",
            ShortDescription: new AdvisorShortDescription(
                Problem: "Storage account should use secure transfer",
                Solution: "Enable secure transfer required"),
            ResourceMetadata: new AdvisorResourceMetadata(
                ResourceId: "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/mystorageaccount",
                Source: null),
            SuppressionIds: null));

    private static SecurityPricing CreateSecurityPricing(string name = "VirtualMachines", string pricingTier = "Standard") => new(
        Id: $"/subscriptions/00000000-0000-0000-0000-000000000000/providers/Microsoft.Security/pricings/{name}",
        Name: name,
        Type: "Microsoft.Security/pricings",
        Properties: new SecurityPricingProperties(
            PricingTier: pricingTier,
            SubPlan: null,
            FreeTrialRemainingTime: null,
            Deprecated: null));

    private static CommandContext CreateCommandContext()
    {
        var remainingArguments = Mock.Of<IRemainingArguments>();
        return new CommandContext([], remainingArguments, "advisor", null);
    }
}
