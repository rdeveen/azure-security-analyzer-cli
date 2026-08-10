using AzureSecurityAnalyzer.OutputFormatters;

using AwesomeAssertions;
using Spectre.Console;

namespace AzureSecurityAnalyzer.Tests.OutputFormatters;

[Collection("ConsoleOutputTests")]
public class ConsoleOutputFormatterTests
{
    private readonly ConsoleOutputFormatter formatter = new();

    [Fact]
    public async Task WriteNetworkSecurityGroups_WithEmptyCollection_WritesMessageWithoutHeaders()
    {
        // Act
        var output = await CaptureAnsiConsoleOutput(() => formatter.WriteNetworkSecurityGroups(
            new AzureSecurityAnalyzer.Commands.NetworkSecurityGroups.Settings(), [], []));

        // Assert
        output.Should().Contain("No network security groups found.");
        output.Should().NotContain("Resource Group");
    }

    [Fact]
    public async Task WriteNetworkSecurityGroups_WithNetworkSecurityGroups_WritesTable()
    {
        // Act
        var output = await CaptureAnsiConsoleOutput(() => formatter.WriteNetworkSecurityGroups(
            new AzureSecurityAnalyzer.Commands.NetworkSecurityGroups.Settings(),
            [MarkdownOutputFormatterTests.CreateNetworkSecurityGroup()], []));

        // Assert
        output.Should().Contain("Resource Group");
        output.Should().Contain("nsg1");
        output.Should().NotContain("No network security groups found.");
    }

    [Fact]
    public async Task WriteAdvisorRecommendations_WithEmptyCollection_WritesMessageWithoutHeaders()
    {
        // Act
        var output = await CaptureAnsiConsoleOutput(() => formatter.WriteAdvisorRecommendations(
            new AzureSecurityAnalyzer.Commands.AdvisorRecommendations.Settings(), []));

        // Assert
        output.Should().Contain("No recommendations found.");
        output.Should().NotContain("Category");
    }

    [Fact]
    public async Task WriteAdvisorRecommendations_WithRecommendations_WritesTable()
    {
        // Act
        var output = await CaptureAnsiConsoleOutput(() => formatter.WriteAdvisorRecommendations(
            new AzureSecurityAnalyzer.Commands.AdvisorRecommendations.Settings(),
            [MarkdownOutputFormatterTests.CreateRecommendation()]));

        // Assert
        output.Should().Contain("Category");
        output.Should().Contain("mystorageaccount");
        output.Should().NotContain("No recommendations found.");
    }

    private static async Task<string> CaptureAnsiConsoleOutput(Func<Task> action)
    {
        var originalConsole = AnsiConsole.Console;
        using var writer = new StringWriter();
        AnsiConsole.Console = AnsiConsole.Create(new AnsiConsoleSettings
        {
            Ansi = AnsiSupport.No,
            ColorSystem = ColorSystemSupport.NoColors,
            Interactive = InteractionSupport.No,
            Out = new AnsiConsoleOutput(writer)
        });

        try
        {
            await action();
        }
        finally
        {
            AnsiConsole.Console = originalConsole;
        }

        return writer.ToString();
    }
}
