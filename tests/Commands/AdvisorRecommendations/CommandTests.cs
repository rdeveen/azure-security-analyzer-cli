using AzureSecurityAnalyzer.Commands.AdvisorRecommendations;
using Command = AzureSecurityAnalyzer.Commands.AdvisorRecommendations.Command;
using AzureSecurityAnalyzer.ManagementApi;
using AzureSecurityAnalyzer.OutputFormatters;

using Shouldly;
using Moq;
using Spectre.Console.Cli;

namespace AzureSecurityAnalyzer.Tests.Commands.AdvisorRecommendations;

public class CommandTests
{
    private readonly Mock<IAzureResourceRetriever> mockAzureResourceRetriever;
    private readonly Command command;

    public CommandTests()
    {
        mockAzureResourceRetriever = new Mock<IAzureResourceRetriever>();
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
    public async Task ExecuteAsync_CallsResourceRetriever_Once()
    {
        // Arrange
        var subscriptionId = Guid.NewGuid();
        mockAzureResourceRetriever
            .Setup(r => r.RetrieveAdvisorRecommendations(It.IsAny<bool>(), subscriptionId, It.IsAny<AzureSecurityAnalyzer.Commands.Scope>()))
            .ReturnsAsync([CreateRecommendation()]);
        var settings = new Settings { Quiet = true, Subscription = subscriptionId };

        // Act
        await ExecuteAsync(settings);

        // Assert
        mockAzureResourceRetriever.Verify(r => r.RetrieveAdvisorRecommendations(It.IsAny<bool>(), subscriptionId, It.IsAny<AzureSecurityAnalyzer.Commands.Scope>()), Times.Once);
    }

    [Fact]
    public async Task ExecuteAsync_ConfiguresRetriever_FromSettings()
    {
        // Arrange
        var subscriptionId = Guid.NewGuid();
        mockAzureResourceRetriever
            .Setup(r => r.RetrieveAdvisorRecommendations(It.IsAny<bool>(), subscriptionId, It.IsAny<AzureSecurityAnalyzer.Commands.Scope>()))
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
    public async Task ExecuteAsync_WithRecommendations_ReturnsZero()
    {
        // Arrange
        var subscriptionId = Guid.NewGuid();
        mockAzureResourceRetriever
            .Setup(r => r.RetrieveAdvisorRecommendations(It.IsAny<bool>(), subscriptionId, It.IsAny<AzureSecurityAnalyzer.Commands.Scope>()))
            .ReturnsAsync([CreateRecommendation(), CreateRecommendation(category: "Cost", impact: "Medium")]);
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
            .Setup(r => r.RetrieveAdvisorRecommendations(It.IsAny<bool>(), subscriptionId, It.IsAny<AzureSecurityAnalyzer.Commands.Scope>()))
            .ReturnsAsync([]);
        var settings = new Settings { Quiet = true, Subscription = subscriptionId };

        // Act
        var result = await ExecuteAsync(settings);

        // Assert
        result.ShouldBe(0);
        mockAzureResourceRetriever.Verify(r => r.RetrieveAdvisorRecommendations(It.IsAny<bool>(), subscriptionId, It.IsAny<AzureSecurityAnalyzer.Commands.Scope>()), Times.Once);
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
            .Setup(r => r.RetrieveAdvisorRecommendations(It.IsAny<bool>(), subscriptionId, It.IsAny<AzureSecurityAnalyzer.Commands.Scope>()))
            .ReturnsAsync([CreateRecommendation()]);
        var settings = new Settings { Quiet = true, Subscription = subscriptionId, Output = outputFormat };

        // Act
        var result = await ExecuteAsync(settings);

        // Assert
        result.ShouldBe(0);
        mockAzureResourceRetriever.Verify(r => r.RetrieveAdvisorRecommendations(It.IsAny<bool>(), subscriptionId, It.IsAny<AzureSecurityAnalyzer.Commands.Scope>()), Times.Once);
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
            .Setup(r => r.RetrieveAdvisorRecommendations(It.IsAny<bool>(), subscriptionId, It.IsAny<AzureSecurityAnalyzer.Commands.Scope>()))
            .ReturnsAsync([recommendation]);
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
            .Setup(r => r.RetrieveAdvisorRecommendations(It.IsAny<bool>(), subscriptionId, It.IsAny<AzureSecurityAnalyzer.Commands.Scope>()))
            .ThrowsAsync(new HttpRequestException("API unavailable"));
        var settings = new Settings { Quiet = true, Subscription = subscriptionId };

        // Act & Assert
        var exception = await Should.ThrowAsync<HttpRequestException>(() => ExecuteAsync(settings));
        exception.Message.ShouldBe("API unavailable");
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

    private static CommandContext CreateCommandContext()
    {
        var remainingArguments = Mock.Of<IRemainingArguments>();
        return new CommandContext([], remainingArguments, "advisor", null);
    }
}
