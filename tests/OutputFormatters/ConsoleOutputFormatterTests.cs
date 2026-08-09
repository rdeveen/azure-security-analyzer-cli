using AzureSecurityAnalyzer.OutputFormatters;

using Shouldly;
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
        output.ShouldContain("No network security groups found.");
        output.ShouldNotContain("Resource Group");
    }

    [Fact]
    public async Task WriteNetworkSecurityGroups_WithNetworkSecurityGroups_WritesTable()
    {
        // Act
        var output = await CaptureAnsiConsoleOutput(() => formatter.WriteNetworkSecurityGroups(
            new AzureSecurityAnalyzer.Commands.NetworkSecurityGroups.Settings(),
            [MarkdownOutputFormatterTests.CreateNetworkSecurityGroup()], []));

        // Assert
        output.ShouldContain("Resource Group");
        output.ShouldContain("nsg1");
        output.ShouldNotContain("No network security groups found.");
    }

    [Fact]
    public async Task WriteAdvisorRecommendations_WithEmptyCollection_WritesMessageWithoutHeaders()
    {
        // Act
        var output = await CaptureAnsiConsoleOutput(() => formatter.WriteAdvisorRecommendations(
            new AzureSecurityAnalyzer.Commands.AdvisorRecommendations.Settings(), []));

        // Assert
        output.ShouldContain("No recommendations found.");
        output.ShouldNotContain("Category");
    }

    [Fact]
    public async Task WriteAdvisorRecommendations_WithRecommendations_WritesTable()
    {
        // Act
        var output = await CaptureAnsiConsoleOutput(() => formatter.WriteAdvisorRecommendations(
            new AzureSecurityAnalyzer.Commands.AdvisorRecommendations.Settings(),
            [MarkdownOutputFormatterTests.CreateRecommendation()]));

        // Assert
        output.ShouldContain("Category");
        output.ShouldContain("mystorageaccount");
        output.ShouldNotContain("No recommendations found.");
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
