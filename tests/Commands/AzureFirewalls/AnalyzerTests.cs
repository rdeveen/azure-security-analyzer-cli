using AzureSecurityAnalyzer.Commands.AzureFirewalls;
using AzureSecurityAnalyzer.ManagementApi;
using AwesomeAssertions;

namespace AzureSecurityAnalyzer.Tests.Commands.AzureFirewalls;

public class AnalyzerTests
{
    [Fact]
    public async Task Analyze_WithIntrusionDetectionOff_ReturnsIntrusionDetectionAnomaly()
    {
        var firewallPolicy = CreateFirewallPolicy();
        var azureFirewall = CreateAzureFirewall(firewallPolicy.Id);
        var ruleCollectionGroups = CreateRuleCollectionGroups();

        var results = await Analyzer.Analyze([firewallPolicy], [azureFirewall], new Dictionary<string, IReadOnlyCollection<FirewallPolicyRuleCollectionGroup>>
        {
            [firewallPolicy.Id] = ruleCollectionGroups
        });

        results.Should().ContainSingle(r => r.IssueDescription == "This Firewall Policy does not have intrusion detection configured in alert or deny mode.");
    }

    [Fact]
    public async Task Analyze_WithoutAttachedFirewall_ReturnsUnusedPolicyAnomaly()
    {
        var firewallPolicy = CreateFirewallPolicy(intrusionDetectionMode: "Alert");

        var results = await Analyzer.Analyze([firewallPolicy], [], new Dictionary<string, IReadOnlyCollection<FirewallPolicyRuleCollectionGroup>>
        {
            [firewallPolicy.Id] = CreateRuleCollectionGroups()
        });

        results.Should().ContainSingle(r => r.IssueDescription == "This Firewall Policy is not attached to any Azure Firewall.");
    }

    [Fact]
    public async Task Analyze_WithoutRules_ReturnsMissingRulesAnomaly()
    {
        var firewallPolicy = CreateFirewallPolicy(intrusionDetectionMode: "Deny");
        var azureFirewall = CreateAzureFirewall(firewallPolicy.Id);

        var results = await Analyzer.Analyze([firewallPolicy], [azureFirewall], new Dictionary<string, IReadOnlyCollection<FirewallPolicyRuleCollectionGroup>>
        {
            [firewallPolicy.Id] = [CreateRuleCollectionGroup(ruleCollections: [])]
        });

        results.Should().ContainSingle(r => r.IssueDescription == "This Firewall Policy does not contain any rules.");
    }

    [Fact]
    public async Task Analyze_WithAllowAllRule_ReturnsAllowAllAnomaly()
    {
        var firewallPolicy = CreateFirewallPolicy(intrusionDetectionMode: "Alert");
        var azureFirewall = CreateAzureFirewall(firewallPolicy.Id);

        var results = await Analyzer.Analyze([firewallPolicy], [azureFirewall], new Dictionary<string, IReadOnlyCollection<FirewallPolicyRuleCollectionGroup>>
        {
            [firewallPolicy.Id] =
            [
                CreateRuleCollectionGroup(
                    ruleCollections:
                    [
                        CreateRuleCollection(
                            name: "allow-collection",
                            actionType: "Allow",
                            rules:
                            [
                                CreateRule(
                                    name: "allow-all-network",
                                    ruleType: "NetworkRule",
                                    sourceAddresses: ["*"],
                                    destinationAddresses: ["*"],
                                    destinationPorts: ["*"])
                            ])
                    ])
            ]
        });

        results.Should().ContainSingle(r => r.IssueDescription == "This Firewall Policy contains an allow-all rule 'allow-all-network' in rule collection 'allow-collection'.");
    }

    [Fact]
    public async Task Analyze_WithAttachedFirewallAndRulesInAlertMode_ReturnsNoAnomalies()
    {
        var firewallPolicy = CreateFirewallPolicy(intrusionDetectionMode: "Alert");
        var azureFirewall = CreateAzureFirewall(firewallPolicy.Id);

        var results = await Analyzer.Analyze([firewallPolicy], [azureFirewall], new Dictionary<string, IReadOnlyCollection<FirewallPolicyRuleCollectionGroup>>
        {
            [firewallPolicy.Id] = CreateRuleCollectionGroups()
        });

        results.Should().BeEmpty();
    }

    private static FirewallPolicy CreateFirewallPolicy(
        string name = "policy1",
        string? intrusionDetectionMode = "Off") => new(
        Id: $"/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg1/providers/Microsoft.Network/firewallPolicies/{name}",
        Name: name,
        Type: "Microsoft.Network/firewallPolicies",
        Location: "westeurope",
        Tags: null,
        Properties: new FirewallPolicyProperties(
            ThreatIntelMode: "Alert",
            IntrusionDetection: new FirewallPolicyIntrusionDetection(intrusionDetectionMode)));

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
        CreateRuleCollectionGroup(
            ruleCollections:
            [
                CreateRuleCollection(
                    actionType: "Allow",
                    rules:
                    [
                        CreateRule(
                            sourceAddresses: ["10.0.0.0/24"],
                            destinationAddresses: ["10.0.1.0/24"],
                            destinationPorts: ["443"])
                    ])
            ])
    ];

    private static FirewallPolicyRuleCollectionGroup CreateRuleCollectionGroup(
        string name = "group1",
        FirewallPolicyRuleCollection[]? ruleCollections = null) => new(
        Id: $"/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg1/providers/Microsoft.Network/firewallPolicies/policy1/ruleCollectionGroups/{name}",
        Name: name,
        Type: "Microsoft.Network/firewallPolicies/ruleCollectionGroups",
        Properties: new FirewallPolicyRuleCollectionGroupProperties(
            Priority: 100,
            RuleCollections: ruleCollections,
            ProvisioningState: "Succeeded"));

    private static FirewallPolicyRuleCollection CreateRuleCollection(
        string name = "collection1",
        string actionType = "Allow",
        FirewallPolicyRule[]? rules = null) => new(
        RuleCollectionType: "FirewallPolicyFilterRuleCollection",
        Name: name,
        Priority: 100,
        Action: new FirewallPolicyRuleCollectionAction(actionType),
        Rules: rules);

    private static FirewallPolicyRule CreateRule(
        string name = "rule1",
        string ruleType = "NetworkRule",
        string[]? sourceAddresses = null,
        string[]? destinationAddresses = null,
        string[]? destinationPorts = null) => new(
        RuleType: ruleType,
        Name: name,
        SourceAddresses: sourceAddresses,
        DestinationAddresses: destinationAddresses,
        DestinationPorts: destinationPorts,
        TargetFqdns: null,
        TargetUrls: null);
}
