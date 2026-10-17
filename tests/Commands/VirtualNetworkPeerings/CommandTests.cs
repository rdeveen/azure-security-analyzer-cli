using AzureSecurityAnalyzer.Commands;
using AzureSecurityAnalyzer.Commands.VirtualNetworkPeerings;
using AzureSecurityAnalyzer.ManagementApi;
using AwesomeAssertions;
using AzureSecurityAnalyzer.OutputFormatters;
using Moq;
using Spectre.Console;
using Spectre.Console.Cli;
using Command = AzureSecurityAnalyzer.Commands.VirtualNetworkPeerings.Command;

namespace AzureSecurityAnalyzer.Tests.Commands.VirtualNetworkPeerings;

[Collection("ConsoleOutputTests")]
public class CommandTests
{
    private readonly Mock<IAzureResourceRetriever> mockAzureResourceRetriever = new(MockBehavior.Strict);
    private readonly Command command;

    public CommandTests()
    {
        mockAzureResourceRetriever.SetupAllProperties();
        command = new Command(mockAzureResourceRetriever.Object);
    }

    [Fact]
    public async Task ExecuteAsync_CallsRetrieverAndConfiguresItFromSettings()
    {
        var subscriptionId = Guid.NewGuid();
        mockAzureResourceRetriever
            .Setup(retriever => retriever.RetrieveVirtualNetworks(It.IsAny<bool>(), subscriptionId))
            .ReturnsAsync([]);
        var settings = new Settings
        {
            Quiet = true,
            Subscription = subscriptionId,
            ManagementApiAddress = "https://management.example.com/",
            HttpTimeout = 42,
            Output = OutputFormat.Json
        };

        var result = await CaptureAnsiConsoleOutput(() => ExecuteAsync(settings));

        result.Should().Be(0);
        mockAzureResourceRetriever.Verify(retriever =>
            retriever.RetrieveVirtualNetworks(It.IsAny<bool>(), subscriptionId), Times.Once);
        mockAzureResourceRetriever.VerifySet(retriever =>
            retriever.ManagementApiAddress = "https://management.example.com/", Times.Once);
        mockAzureResourceRetriever.VerifySet(retriever =>
            retriever.HttpTimeout = TimeSpan.FromSeconds(42), Times.Once);
    }

    [Theory]
    [InlineData(OutputFormat.Console)]
    [InlineData(OutputFormat.Json)]
    [InlineData(OutputFormat.Jsonc)]
    [InlineData(OutputFormat.Markdown)]
    public async Task ExecuteAsync_WithPeeringsSupportsOutputFormats(OutputFormat outputFormat)
    {
        var subscriptionId = Guid.NewGuid();
        mockAzureResourceRetriever
            .Setup(retriever => retriever.RetrieveVirtualNetworks(It.IsAny<bool>(), subscriptionId))
            .ReturnsAsync([CreateVirtualNetwork()]);
        var settings = new Settings { Quiet = true, Subscription = subscriptionId, Output = outputFormat };

        var result = await CaptureAnsiConsoleOutput(() => ExecuteAsync(settings));

        result.Should().Be(0);
    }

    private Task<int> ExecuteAsync(Settings settings) =>
        ((ICommand<Settings>)command).ExecuteAsync(CreateCommandContext(), settings, CancellationToken.None);

    private static async Task<T> CaptureAnsiConsoleOutput<T>(Func<Task<T>> action)
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
            return await action();
        }
        finally
        {
            AnsiConsole.Console = originalConsole;
        }
    }

    private static VirtualNetwork CreateVirtualNetwork() => new(
        Id: "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Network/virtualNetworks/vnet1",
        Name: "vnet1",
        Type: "Microsoft.Network/virtualNetworks",
        Location: "westeurope",
        Tags: null,
        Properties: new VirtualNetworkProperties("Succeeded",
        [
            new VirtualNetworkPeering(
                Id: "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Network/virtualNetworks/vnet1/virtualNetworkPeerings/peer1",
                Name: "peer1",
                Type: "Microsoft.Network/virtualNetworks/virtualNetworkPeerings",
                Properties: new VirtualNetworkPeeringProperties(
                    PeeringState: "Connected",
                    AllowVirtualNetworkAccess: true,
                    AllowForwardedTraffic: true,
                    RemoteVirtualNetwork: new ResourceReference("/subscriptions/sub1/resourceGroups/rg2/providers/Microsoft.Network/virtualNetworks/vnet2")))
        ]));

    private static CommandContext CreateCommandContext() =>
        new([], Mock.Of<IRemainingArguments>(), "vnet-peerings", null);
}
