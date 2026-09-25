using AzureSecurityAnalyzer.Commands.NetworkSecurityGroups;
using Command = AzureSecurityAnalyzer.Commands.NetworkSecurityGroups.Command;
using AzureSecurityAnalyzer.ManagementApi;
using AzureSecurityAnalyzer.OutputFormatters;

using AwesomeAssertions;
using Moq;
using Spectre.Console;
using Spectre.Console.Cli;
using AzureSecurityAnalyzer.Commands;

namespace AzureSecurityAnalyzer.Tests.Commands.NetworkSecurityGroups;

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
    public void NetworkSecurityGroupsSettings_DefaultValues_AreSetCorrectly()
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
            .Setup(r => r.RetrieveNetworkSecurityGroups(It.IsAny<bool>(), subscriptionId))
            .ReturnsAsync([CreateNetworkSecurityGroup()]);
        var settings = new Settings { Quiet = true, Subscription = subscriptionId };

        // Act
        await CaptureAnsiConsoleOutput(() => ExecuteAsync(settings));

        // Assert
        mockAzureResourceRetriever.Verify(r => r.RetrieveNetworkSecurityGroups(It.IsAny<bool>(), subscriptionId), Times.Once);
    }

    [Fact]
    public async Task ExecuteAsync_ConfiguresRetriever_FromSettings()
    {
        // Arrange
        var subscriptionId = Guid.NewGuid();
        mockAzureResourceRetriever
            .Setup(r => r.RetrieveNetworkSecurityGroups(It.IsAny<bool>(), subscriptionId))
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
    public async Task ExecuteAsync_WithNetworkSecurityGroups_ReturnsZero()
    {
        // Arrange
        var subscriptionId = Guid.NewGuid();
        mockAzureResourceRetriever
            .Setup(r => r.RetrieveNetworkSecurityGroups(It.IsAny<bool>(), subscriptionId))
            .ReturnsAsync([CreateNetworkSecurityGroup(), CreateNetworkSecurityGroup(name: "nsg2")]);
        var settings = new Settings { Quiet = true, Subscription = subscriptionId };

        // Act
        var result = await CaptureAnsiConsoleOutput(() => ExecuteAsync(settings));

        // Assert
        result.Should().Be(0);
    }

    [Fact]
    public async Task ExecuteAsync_WithEmptyNetworkSecurityGroups_ReturnsZero()
    {
        // Arrange
        var subscriptionId = Guid.NewGuid();
        mockAzureResourceRetriever
            .Setup(r => r.RetrieveNetworkSecurityGroups(It.IsAny<bool>(), subscriptionId))
            .ReturnsAsync([]);
        var settings = new Settings { Quiet = true, Subscription = subscriptionId };

        // Act
        var result = await CaptureAnsiConsoleOutput(() => ExecuteAsync(settings));

        // Assert
        result.Should().Be(0);
        mockAzureResourceRetriever.Verify(r => r.RetrieveNetworkSecurityGroups(It.IsAny<bool>(), subscriptionId), Times.Once);
    }

    [Fact]
    public async Task ExecuteAsync_WithNetworkSecurityGroupAnomalyScenarios_ReturnsZero()
    {
        // Arrange
        var subscriptionId = Guid.NewGuid();
        mockAzureResourceRetriever
            .Setup(r => r.RetrieveNetworkSecurityGroups(It.IsAny<bool>(), subscriptionId))
            .ReturnsAsync(
            [
                CreateNetworkSecurityGroup(name: "nsg-no-rules", securityRules: []),
                CreateNetworkSecurityGroup(
                    name: "nsg-open",
                    securityRules:
                    [
                        CreateSecurityRule(
                            name: "allow-all-inbound",
                            access: "Allow",
                            direction: "Inbound",
                            sourceAddressPrefix: "*",
                            destinationAddressPrefix: "*",
                            sourcePortRange: "*",
                            destinationPortRange: "*")
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
            .Setup(r => r.RetrieveNetworkSecurityGroups(It.IsAny<bool>(), subscriptionId))
            .ReturnsAsync([CreateNetworkSecurityGroup()]);
        var settings = new Settings { Quiet = true, Subscription = subscriptionId, Output = outputFormat };

        // Act
        var result = await CaptureAnsiConsoleOutput(() => ExecuteAsync(settings));

        // Assert
        result.Should().Be(0);
        mockAzureResourceRetriever.Verify(r => r.RetrieveNetworkSecurityGroups(It.IsAny<bool>(), subscriptionId), Times.Once);
    }

    [Fact]
    public async Task ExecuteAsync_WhenRetrieverThrows_PropagatesException()
    {
        // Arrange
        var subscriptionId = Guid.NewGuid();
        mockAzureResourceRetriever
            .Setup(r => r.RetrieveNetworkSecurityGroups(It.IsAny<bool>(), subscriptionId))
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

    private static NetworkSecurityGroup CreateNetworkSecurityGroup(
        string name = "nsg1",
        SecurityRule[]? securityRules = null,
        ResourceReference[]? subnets = null) => new(
        Id: $"/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg1/providers/Microsoft.Network/networkSecurityGroups/{name}",
        Name: name,
        Type: "Microsoft.Network/networkSecurityGroups",
        Location: "westeurope",
        Tags: null,
        Properties: new NetworkSecurityGroupProperties(
            ProvisioningState: "Succeeded",
            ResourceGuid: Guid.NewGuid().ToString(),
            SecurityRules: securityRules ?? [CreateSecurityRule()],
            DefaultSecurityRules: null,
            NetworkInterfaces: null,
            Subnets: subnets ?? [new ResourceReference("/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg1/providers/Microsoft.Network/virtualNetworks/vnet1/subnets/subnet1")]));

    private static SecurityRule CreateSecurityRule(
        string name = "rule1",
        string access = "Allow",
        string direction = "Inbound",
        string? sourceAddressPrefix = "10.0.0.0/24",
        string? destinationAddressPrefix = "10.0.1.0/24",
        string? sourcePortRange = "*",
        string? destinationPortRange = "443",
        int priority = 100) =>
        new(
            Id: $"/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg1/providers/Microsoft.Network/networkSecurityGroups/nsg1/securityRules/{name}",
            Name: name,
            Type: "Microsoft.Network/networkSecurityGroups/securityRules",
            Properties: new SecurityRuleProperties(
                ProvisioningState: "Succeeded",
                Description: null,
                Protocol: "Tcp",
                SourcePortRange: sourcePortRange,
                DestinationPortRange: destinationPortRange,
                SourceAddressPrefix: sourceAddressPrefix,
                DestinationAddressPrefix: destinationAddressPrefix,
                Access: access,
                Priority: priority,
                Direction: direction,
                SourcePortRanges: null,
                DestinationPortRanges: null,
                SourceAddressPrefixes: null,
                DestinationAddressPrefixes: null));

    private static CommandContext CreateCommandContext()
    {
        var remainingArguments = Mock.Of<IRemainingArguments>();
        return new CommandContext([], remainingArguments, "network-security-groups", null);
    }
}
