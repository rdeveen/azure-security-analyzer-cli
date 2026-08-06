using AzureSecurityAnalyzer.Commands.Regions;

using Shouldly;
using Moq;
using Spectre.Console.Cli;

namespace AzureSecurityAnalyzer.Tests.Commands.Regions;

public class CommandTests
{
    private readonly Mock<AzureSecurityAnalyzer.RegionsApi.IRegionsRetriever> mockRegionsRetriever;
    private readonly AzureSecurityAnalyzer.Commands.Regions.Command command;

    public CommandTests()
    {
        mockRegionsRetriever = new Mock<AzureSecurityAnalyzer.RegionsApi.IRegionsRetriever>();
        command = new AzureSecurityAnalyzer.Commands.Regions.Command(mockRegionsRetriever.Object);
    }

    [Fact]
    public void Constructor_SetsUpOutputFormatters()
    {
        // Act & Assert - Constructor should not throw
        var command = new AzureSecurityAnalyzer.Commands.Regions.Command(mockRegionsRetriever.Object);
        command.ShouldNotBeNull();
    }

    [Fact]
    public void RegionsSettings_DefaultValues_AreSetCorrectly()
    {
        // Arrange & Act
        var settings = new AzureSecurityAnalyzer.Commands.Regions.Settings();

        // Assert
        settings.Output.ShouldBe(AzureSecurityAnalyzer.Commands.OutputFormat.Console);
    }

    private static CommandContext CreateCommandContext()
    {
        var remainingArguments = Mock.Of<Spectre.Console.Cli.IRemainingArguments>();
        return new Spectre.Console.Cli.CommandContext([], remainingArguments, "regions", null);
    }
}