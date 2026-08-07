using AzureSecurityAnalyzer.Commands.Regions;
using Command = AzureSecurityAnalyzer.Commands.Regions.Command;
using AzureSecurityAnalyzer.RegionsApi;

using Shouldly;
using Moq;
using Spectre.Console.Cli;

namespace AzureSecurityAnalyzer.Tests.Commands.Regions;

public class CommandTests
{
    private readonly Mock<IRegionsRetriever> mockRegionsRetriever;
    private readonly Command command;

    public CommandTests()
    {
        mockRegionsRetriever = new Mock<IRegionsRetriever>();
        command = new Command(mockRegionsRetriever.Object);
    }

    [Fact]
    public void Constructor_SetsUpOutputFormatters()
    {
        // Act & Assert - Constructor should not throw
        var command = new Command(mockRegionsRetriever.Object);
        command.ShouldNotBeNull();
    }

    [Fact]
    public void RegionsSettings_DefaultValues_AreSetCorrectly()
    {
        // Arrange & Act
        var settings = new Settings();

        // Assert
        settings.Output.ShouldBe(AzureSecurityAnalyzer.Commands.OutputFormat.Console);
    }

    [Fact]
    public async Task ExecuteAsync_CallsRegionsRetriever_Once()
    {
        // Arrange
        mockRegionsRetriever
            .Setup(r => r.RetrieveRegions())
            .ReturnsAsync([CreateRegion("westeurope")]);
        var settings = new Settings { Quiet = true };

        // Act
        await ExecuteAsync(settings);

        // Assert
        mockRegionsRetriever.Verify(r => r.RetrieveRegions(), Times.Once);
    }

    [Fact]
    public async Task ExecuteAsync_WithRegions_ReturnsZero()
    {
        // Arrange
        mockRegionsRetriever
            .Setup(r => r.RetrieveRegions())
            .ReturnsAsync([CreateRegion("westeurope"), CreateRegion("eastus", isOpen: false)]);
        var settings = new Settings { Quiet = true };

        // Act
        var result = await ExecuteAsync(settings);

        // Assert
        result.ShouldBe(0);
    }

    [Fact]
    public async Task ExecuteAsync_WithEmptyRegions_ReturnsZero()
    {
        // Arrange
        mockRegionsRetriever
            .Setup(r => r.RetrieveRegions())
            .ReturnsAsync([]);
        var settings = new Settings { Quiet = true };

        // Act
        var result = await ExecuteAsync(settings);

        // Assert
        result.ShouldBe(0);
        mockRegionsRetriever.Verify(r => r.RetrieveRegions(), Times.Once);
    }

    [Theory]
    [InlineData(AzureSecurityAnalyzer.Commands.OutputFormat.Console)]
    [InlineData(AzureSecurityAnalyzer.Commands.OutputFormat.Json)]
    [InlineData(AzureSecurityAnalyzer.Commands.OutputFormat.Jsonc)]
    [InlineData(AzureSecurityAnalyzer.Commands.OutputFormat.Markdown)]
    public async Task ExecuteAsync_WithSupportedOutputFormats_ReturnsZero(AzureSecurityAnalyzer.Commands.OutputFormat outputFormat)
    {
        // Arrange
        mockRegionsRetriever
            .Setup(r => r.RetrieveRegions())
            .ReturnsAsync([CreateRegion("westeurope")]);
        var settings = new Settings { Quiet = true, Output = outputFormat };

        // Act
        var result = await ExecuteAsync(settings);

        // Assert
        result.ShouldBe(0);
        mockRegionsRetriever.Verify(r => r.RetrieveRegions(), Times.Once);
    }

    [Fact]
    public async Task ExecuteAsync_WhenRetrieverThrows_PropagatesException()
    {
        // Arrange
        mockRegionsRetriever
            .Setup(r => r.RetrieveRegions())
            .ThrowsAsync(new HttpRequestException("API unavailable"));
        var settings = new Settings { Quiet = true };

        // Act & Assert
        var exception = await Should.ThrowAsync<HttpRequestException>(() => ExecuteAsync(settings));
        exception.Message.ShouldBe("API unavailable");
    }

    private Task<int> ExecuteAsync(Settings settings)
    {
        return ((ICommand<Settings>)command).ExecuteAsync(CreateCommandContext(), settings, CancellationToken.None);
    }

    private static AzureRegion CreateRegion(string id, bool isOpen = true) => new(
        Id: id,
        Continent: "Europe",
        GeographyId: "netherlands",
        DisplayName: "West Europe",
        Location: "Netherlands",
        Latitude: 52.3667,
        Longitude: 4.9,
        TypeId: "physical",
        IsOpen: isOpen,
        YearOpen: 2010,
        ComplianceIds: ["iso-27001", "gdpr"],
        HasGroundStation: false,
        DataResidency: "Netherlands",
        AvailableTo: "All",
        AvailabilityZonesId: "with-availability-zones",
        AvailabilityZonesNearestRegionIds: ["northeurope"],
        ProductsByRegionLink: "https://example.com/products",
        ProductsByRegionLinkNonRegional: "https://example.com/products-non-regional",
        SustainabilityIds: ["renewable-energy"],
        DisasterRecoveryCrossRegionIds: ["northeurope"],
        DisasterRecoveryInRegionIds: []);

    private static CommandContext CreateCommandContext()
    {
        var remainingArguments = Mock.Of<IRemainingArguments>();
        return new CommandContext([], remainingArguments, "regions", null);
    }
}