using AzureSecurityAnalyzer.Commands;
using AzureSecurityAnalyzer.Commands.AzureFirewalls;
using AzureSecurityAnalyzer.ManagementApi;
using AwesomeAssertions;
using Moq;
using Spectre.Console;
using Spectre.Console.Cli;
using Command = AzureSecurityAnalyzer.Commands.AzureFirewalls.Command;

namespace AzureSecurityAnalyzer.Tests.Commands.AzureFirewalls;

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
    public void AzureFirewallsSettings_DefaultValues_AreSetCorrectly()
    {
        var settings = new Settings();

        settings.Output.Should().Be(OutputFormat.Console);
        settings.ManagementApiAddress.Should().Be("https://management.azure.com/");
        settings.HttpTimeout.Should().Be(100);
    }

    [Fact]
    public async Task ExecuteAsync_CallsResourceRetrieverMethods()
    {
        var subscriptionId = Guid.NewGuid();
        var firewallPolicy = CreateFirewallPolicy();

        mockAzureResourceRetriever
            .Setup(r => r.RetrieveAzureFirewalls(It.IsAny<bool>(), subscriptionId))
            .ReturnsAsync([CreateAzureFirewall(firewallPolicy.Id)]);
        mockAzureResourceRetriever
            .Setup(r => r.RetrieveFirewallPolicies(It.IsAny<bool>(), subscriptionId))
            .ReturnsAsync([firewallPolicy]);
        mockAzureResourceRetriever
            .Setup(r => r.RetrieveFirewallPolicyRuleCollectionGroups(It.IsAny<bool>(), subscriptionId, "rg1", firewallPolicy.Name))
            .ReturnsAsync(CreateRuleCollectionGroups());

        var settings = new Settings { Quiet = true, Subscription = subscriptionId };

        await CaptureAnsiConsoleOutput(() => ExecuteAsync(settings));

        mockAzureResourceRetriever.Verify(r => r.RetrieveAzureFirewalls(It.IsAny<bool>(), subscriptionId), Times.Once);
        mockAzureResourceRetriever.Verify(r => r.RetrieveFirewallPolicies(It.IsAny<bool>(), subscriptionId), Times.Once);
        mockAzureResourceRetriever.Verify(r => r.RetrieveFirewallPolicyRuleCollectionGroups(It.IsAny<bool>(), subscriptionId, "rg1", firewallPolicy.Name), Times.Once);
    }

    [Theory]
    [InlineData(OutputFormat.Console)]
    [InlineData(OutputFormat.Json)]
    [InlineData(OutputFormat.Jsonc)]
    [InlineData(OutputFormat.Markdown)]
    public async Task ExecuteAsync_WithSupportedOutputFormats_ReturnsZero(OutputFormat outputFormat)
    {
        var subscriptionId = Guid.NewGuid();
        var firewallPolicy = CreateFirewallPolicy();

        mockAzureResourceRetriever
            .Setup(r => r.RetrieveAzureFirewalls(It.IsAny<bool>(), subscriptionId))
            .ReturnsAsync([CreateAzureFirewall(firewallPolicy.Id)]);
        mockAzureResourceRetriever
            .Setup(r => r.RetrieveFirewallPolicies(It.IsAny<bool>(), subscriptionId))
            .ReturnsAsync([firewallPolicy]);
        mockAzureResourceRetriever
            .Setup(r => r.RetrieveFirewallPolicyRuleCollectionGroups(It.IsAny<bool>(), subscriptionId, "rg1", firewallPolicy.Name))
            .ReturnsAsync(CreateRuleCollectionGroups());

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

    private static FirewallPolicy CreateFirewallPolicy(string name = "policy1") => new(
        Id: $"/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg1/providers/Microsoft.Network/firewallPolicies/{name}",
        Name: name,
        Type: "Microsoft.Network/firewallPolicies",
        Location: "westeurope",
        Tags: null,
        Properties: new FirewallPolicyProperties(
            ThreatIntelMode: "Alert",
            IntrusionDetection: new FirewallPolicyIntrusionDetection("Alert")));

    private static AzureFirewall CreateAzureFirewall(string firewallPolicyId, string name = "fw1") => new(
        Id: $"/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg1/providers/Microsoft.Network/azureFirewalls/{name}",
        Name: name,
        Type: "Microsoft.Network/azureFirewalls",
        Location: "westeurope",
        Tags: null,
        Properties: new AzureFirewallProperties(
            ProvisioningState: "Succeeded",
            ThreatIntelMode: "Alert",
            FirewallPolicy: new ResourceReference(firewallPolicyId),
            Sku: new AzureFirewallSku("AZFW_VNet", "Premium")));

    private static IReadOnlyCollection<FirewallPolicyRuleCollectionGroup> CreateRuleCollectionGroups() =>
    [
        new FirewallPolicyRuleCollectionGroup(
            Id: "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg1/providers/Microsoft.Network/firewallPolicies/policy1/ruleCollectionGroups/group1",
            Name: "group1",
            Type: "Microsoft.Network/firewallPolicies/ruleCollectionGroups",
            Properties: new FirewallPolicyRuleCollectionGroupProperties(
                Priority: 100,
                RuleCollections:
                [
                    new FirewallPolicyRuleCollection(
                        RuleCollectionType: "FirewallPolicyFilterRuleCollection",
                        Name: "collection1",
                        Priority: 100,
                        Action: new FirewallPolicyRuleCollectionAction("Allow"),
                        Rules:
                        [
                            new FirewallPolicyRule(
                                RuleType: "NetworkRule",
                                Name: "rule1",
                                SourceAddresses: ["10.0.0.0/24"],
                                DestinationAddresses: ["10.0.1.0/24"],
                                DestinationPorts: ["443"],
                                TargetFqdns: null,
                                TargetUrls: null)
                        ])
                ],
                ProvisioningState: "Succeeded"))
    ];

    private static CommandContext CreateCommandContext()
    {
        var remainingArguments = Mock.Of<IRemainingArguments>();
        return new CommandContext([], remainingArguments, "azure-firewalls", null);
    }
}
