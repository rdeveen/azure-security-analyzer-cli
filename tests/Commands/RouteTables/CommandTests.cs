using AzureSecurityAnalyzer.Commands.RouteTables;
using Command = AzureSecurityAnalyzer.Commands.RouteTables.Command;
using AzureSecurityAnalyzer.ManagementApi;
using AzureSecurityAnalyzer.OutputFormatters;

using AwesomeAssertions;
using Moq;
using Spectre.Console;
using Spectre.Console.Cli;
using AzureSecurityAnalyzer.Commands;

namespace AzureSecurityAnalyzer.Tests.Commands.RouteTables;

[Collection("ConsoleOutputTests")]
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
        command.Should().NotBeNull();
    }

    [Fact]
    public void RouteTablesSettings_DefaultValues_AreSetCorrectly()
    {
        // Arrange & Act
        var settings = new Settings();

        // Assert
        settings.Output.Should().Be(OutputFormat.Console);
        settings.ManagementApiAddress.Should().Be("https://management.azure.com/");
        settings.HttpTimeout.Should().Be(100);
    }

    [Fact]
    public async Task ExecuteAsync_CallsResourceRetriever_Once()
    {
        // Arrange
        var subscriptionId = Guid.NewGuid();
        mockAzureResourceRetriever
            .Setup(r => r.RetrieveRouteTables(It.IsAny<bool>(), subscriptionId))
            .ReturnsAsync([CreateRouteTable()]);
        var settings = new Settings { Quiet = true, Subscription = subscriptionId };

        // Act
        await CaptureAnsiConsoleOutput(() => ExecuteAsync(settings));

        // Assert
        mockAzureResourceRetriever.Verify(r => r.RetrieveRouteTables(It.IsAny<bool>(), subscriptionId), Times.Once);
    }

    [Fact]
    public async Task ExecuteAsync_ConfiguresRetriever_FromSettings()
    {
        // Arrange
        var subscriptionId = Guid.NewGuid();
        mockAzureResourceRetriever
            .Setup(r => r.RetrieveRouteTables(It.IsAny<bool>(), subscriptionId))
            .ReturnsAsync([]);
        var settings = new Settings
        {
            Quiet = true,
            Subscription = subscriptionId,
            ManagementApiAddress = "https://management.example.com/",
            HttpTimeout = 42
        };

        // Act
        await CaptureAnsiConsoleOutput(() => ExecuteAsync(settings));

        // Assert
        mockAzureResourceRetriever.VerifySet(r => r.ManagementApiAddress = "https://management.example.com/", Times.Once);
        mockAzureResourceRetriever.VerifySet(r => r.HttpTimeout = TimeSpan.FromSeconds(42), Times.Once);
    }

    [Fact]
    public async Task ExecuteAsync_WithRouteTables_ReturnsZero()
    {
        // Arrange
        var subscriptionId = Guid.NewGuid();
        mockAzureResourceRetriever
            .Setup(r => r.RetrieveRouteTables(It.IsAny<bool>(), subscriptionId))
            .ReturnsAsync([CreateRouteTable(), CreateRouteTable(name: "rt2")]);
        var settings = new Settings { Quiet = true, Subscription = subscriptionId };

        // Act
        var result = await CaptureAnsiConsoleOutput(() => ExecuteAsync(settings));

        // Assert
        result.Should().Be(0);
    }

    [Fact]
    public async Task ExecuteAsync_WithEmptyRouteTables_ReturnsZero()
    {
        // Arrange
        var subscriptionId = Guid.NewGuid();
        mockAzureResourceRetriever
            .Setup(r => r.RetrieveRouteTables(It.IsAny<bool>(), subscriptionId))
            .ReturnsAsync([]);
        var settings = new Settings { Quiet = true, Subscription = subscriptionId };

        // Act
        var result = await CaptureAnsiConsoleOutput(() => ExecuteAsync(settings));

        // Assert
        result.Should().Be(0);
        mockAzureResourceRetriever.Verify(r => r.RetrieveRouteTables(It.IsAny<bool>(), subscriptionId), Times.Once);
    }

    [Fact]
    public async Task ExecuteAsync_WithRouteTableAnalyzerScenarios_ReturnsZero()
    {
        // Arrange
        var subscriptionId = Guid.NewGuid();
        mockAzureResourceRetriever
            .Setup(r => r.RetrieveRouteTables(It.IsAny<bool>(), subscriptionId))
            .ReturnsAsync(
            [
                CreateRouteTable(
                    name: "rt-firewall",
                    routes:
                    [
                        CreateRoute(
                            name: "defaultToFirewall",
                            addressPrefix: "0.0.0.0/0",
                            nextHopType: "VirtualAppliance",
                            nextHopIpAddress: "10.0.0.4")
                    ]),
                CreateRouteTable(
                    name: "rt-internet",
                    routes:
                    [
                        CreateRoute(
                            name: "defaultToInternet",
                            addressPrefix: "0.0.0.0/0",
                            nextHopType: "Internet")
                    ],
                    subnets: [])
            ]);
        var settings = new Settings { Quiet = true, Subscription = subscriptionId, Output = OutputFormat.Json };

        // Act
        var result = await CaptureAnsiConsoleOutput(() => ExecuteAsync(settings));

        // Assert
        result.Should().Be(0);
    }

    [Theory]
    [InlineData(OutputFormat.Console)]
    [InlineData(OutputFormat.Json)]
    [InlineData(OutputFormat.Jsonc)]
    [InlineData(OutputFormat.Markdown)]
    public async Task ExecuteAsync_WithSupportedOutputFormats_ReturnsZero(OutputFormat outputFormat)
    {
        // Arrange
        var subscriptionId = Guid.NewGuid();
        mockAzureResourceRetriever
            .Setup(r => r.RetrieveRouteTables(It.IsAny<bool>(), subscriptionId))
            .ReturnsAsync([CreateRouteTable()]);
        var settings = new Settings { Quiet = true, Subscription = subscriptionId, Output = outputFormat };

        // Act
        var result = await CaptureAnsiConsoleOutput(() => ExecuteAsync(settings));

        // Assert
        result.Should().Be(0);
        mockAzureResourceRetriever.Verify(r => r.RetrieveRouteTables(It.IsAny<bool>(), subscriptionId), Times.Once);
    }

    [Fact]
    public async Task ExecuteAsync_WhenRetrieverThrows_PropagatesException()
    {
        // Arrange
        var subscriptionId = Guid.NewGuid();
        mockAzureResourceRetriever
            .Setup(r => r.RetrieveRouteTables(It.IsAny<bool>(), subscriptionId))
            .ThrowsAsync(new HttpRequestException("API unavailable"));
        var settings = new Settings { Quiet = true, Subscription = subscriptionId };

        // Act & Assert
        await FluentActions.Awaiting(() => ExecuteAsync(settings))
            .Should().ThrowAsync<HttpRequestException>()
            .WithMessage("API unavailable");
    }

    private Task<int> ExecuteAsync(Settings settings)
    {
        return ((ICommand<Settings>)command).ExecuteAsync(CreateCommandContext(), settings, CancellationToken.None);
    }

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

    private static RouteTable CreateRouteTable(
        string name = "rt1",
        Route[]? routes = null,
        ResourceReference[]? subnets = null) => new(
        Id: $"/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg1/providers/Microsoft.Network/routeTables/{name}",
        Name: name,
        Type: "Microsoft.Network/routeTables",
        Location: "westeurope",
        Tags: null,
        Properties: new RouteTableProperties(
            ProvisioningState: "Succeeded",
            Routes: routes ??
            [
                CreateRoute()
            ],
            Subnets: subnets ?? [new ResourceReference("/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg1/providers/Microsoft.Network/virtualNetworks/vnet1/subnets/subnet1")],
            DisableBgpRoutePropagation: false));

    private static Route CreateRoute(
        string name = "route1",
        string? addressPrefix = "10.0.0.0/24",
        string nextHopType = "VirtualNetworkGateway",
        string? nextHopIpAddress = null) =>
        new(
            Id: $"/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg1/providers/Microsoft.Network/routeTables/rt1/routes/{name}",
            Name: name,
            Type: "Microsoft.Network/routeTables/routes",
            Properties: new RouteProperties(
                ProvisioningState: "Succeeded",
                AddressPrefix: addressPrefix,
                NextHopType: nextHopType,
                NextHopIpAddress: nextHopIpAddress));

    private static CommandContext CreateCommandContext()
    {
        var remainingArguments = Mock.Of<IRemainingArguments>();
        return new CommandContext([], remainingArguments, "route-tables", null);
    }
}
