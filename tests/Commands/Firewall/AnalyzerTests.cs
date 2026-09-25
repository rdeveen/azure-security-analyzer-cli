using AzureSecurityAnalyzer.Commands.Firewall;
using AzureSecurityAnalyzer.ManagementApi;
using AwesomeAssertions;

namespace AzureSecurityAnalyzer.Tests.Commands.Firewall;

public class AnalyzerTests
{
    [Fact]
    public async Task Analyze_PremiumPolicyWithIntrusionDetectionDeny_ReturnsNoAnomaly()
    {
        var policy = CreatePolicy(
            sku: "Premium",
            intrusionDetectionMode: "Deny",
            firewalls: [new ResourceReference("/firewalls/fw1")],
            ruleCollectionGroups: [CreateGroupWithAllowRule("net", "*", "10.0.0.0/8")]);

        var results = await Analyzer.Analyze([policy]);

        results.Should().BeEmpty();
    }

    [Fact]
    public async Task Analyze_PremiumPolicyWithIntrusionDetectionAlert_ReturnsDetectionOnlyAnomaly()
    {
        var policy = CreatePolicy(
            sku: "Premium",
            intrusionDetectionMode: "Alert",
            firewalls: [new ResourceReference("/firewalls/fw1")],
            ruleCollectionGroups: [CreateGroupWithAllowRule("net", "10.0.0.0/8", "10.0.0.0/8")]);

        var results = await Analyzer.Analyze([policy]);

        results.Should().ContainSingle();
        results.Single().IssueDescription.Should().Be("This firewall policy has intrusion detection in 'Alert' mode instead of 'Deny'.");
        results.Single().Severity.Should().Be(SeverityLevel.Medium);
    }

    [Fact]
    public async Task Analyze_StandardPolicyWithIntrusionDetectionAlert_SkipsDetectionOnlyRule()
    {
        // Intrusion detection is only relevant on Premium; ensure Standard is skipped.
        var policy = CreatePolicy(
            sku: "Standard",
            intrusionDetectionMode: "Alert",
            firewalls: [new ResourceReference("/firewalls/fw1")],
            ruleCollectionGroups: [CreateGroupWithAllowRule("net", "10.0.0.0/8", "10.0.0.0/8")]);

        var results = await Analyzer.Analyze([policy]);

        results.Should().BeEmpty();
    }

    [Fact]
    public async Task Analyze_PolicyAttachedToFirewall_ReturnsNoUnattachedAnomaly()
    {
        var policy = CreatePolicy(
            sku: "Standard",
            firewalls: [new ResourceReference("/firewalls/fw1")],
            ruleCollectionGroups: [CreateGroupWithAllowRule("net", "10.0.0.0/8", "10.0.0.0/8")]);

        var results = await Analyzer.Analyze([policy]);

        results.Should().BeEmpty();
    }

    [Fact]
    public async Task Analyze_PolicyNotAttachedToFirewall_ReturnsUnattachedAnomaly()
    {
        var policy = CreatePolicy(
            sku: "Standard",
            firewalls: null,
            ruleCollectionGroups: [CreateGroupWithAllowRule("net", "10.0.0.0/8", "10.0.0.0/8")]);

        var results = await Analyzer.Analyze([policy]);

        results.Should().ContainSingle();
        results.Single().IssueDescription.Should().Be("This firewall policy is not attached to any firewall.");
        results.Single().Severity.Should().Be(SeverityLevel.Low);
    }

    [Fact]
    public async Task Analyze_PolicyWithRules_ReturnsNoEmptyPolicyAnomaly()
    {
        var policy = CreatePolicy(
            sku: "Standard",
            firewalls: [new ResourceReference("/firewalls/fw1")],
            ruleCollectionGroups: [CreateGroupWithAllowRule("net", "10.0.0.0/8", "10.0.0.0/8")]);

        var results = await Analyzer.Analyze([policy]);

        results.Should().BeEmpty();
    }

    [Fact]
    public async Task Analyze_PolicyWithNoRuleCollectionGroups_ReturnsEmptyPolicyAnomaly()
    {
        var policy = CreatePolicy(
            sku: "Standard",
            firewalls: [new ResourceReference("/firewalls/fw1")],
            ruleCollectionGroups: []);

        var results = await Analyzer.Analyze([policy]);

        results.Should().ContainSingle();
        results.Single().IssueDescription.Should().Be("This firewall policy has no rules configured.");
        results.Single().Severity.Should().Be(SeverityLevel.Medium);
    }

    [Fact]
    public async Task Analyze_PolicyWithAllowSpecificRule_ReturnsNoAllowAllAnomaly()
    {
        var policy = CreatePolicy(
            sku: "Standard",
            firewalls: [new ResourceReference("/firewalls/fw1")],
            ruleCollectionGroups: [CreateGroupWithAllowRule("net", "10.0.0.0/24", "10.0.1.0/24", destinationPorts: ["443"])]);

        var results = await Analyzer.Analyze([policy]);

        results.Should().BeEmpty();
    }

    [Fact]
    public async Task Analyze_PolicyWithAllowAllRule_ReturnsAllowAllAnomaly()
    {
        var policy = CreatePolicy(
            sku: "Standard",
            firewalls: [new ResourceReference("/firewalls/fw1")],
            ruleCollectionGroups: [CreateGroupWithAllowRule("allowAll", "*", "*", destinationPorts: ["*"])]);

        var results = await Analyzer.Analyze([policy]);

        results.Should().ContainSingle();
        results.Single().IssueDescription.Should().Be("This firewall policy has an allow-all rule 'allowAll' in rule collection 'rc1'.");
        results.Single().Severity.Should().Be(SeverityLevel.High);
    }

    private static FirewallPolicy CreatePolicy(
        string sku,
        ResourceReference[]? firewalls,
        FirewallPolicyRuleCollectionGroup[] ruleCollectionGroups,
        string? intrusionDetectionMode = "Deny") => new(
        Id: "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Network/firewallPolicies/fp1",
        Name: "fp1",
        Type: "Microsoft.Network/firewallPolicies",
        Location: "westeurope",
        Tags: null,
        Sku: new FirewallPolicySku(sku),
        Properties: new FirewallPolicyProperties(
            ProvisioningState: "Succeeded",
            Firewalls: firewalls,
            RuleCollectionGroups: null,
            IntrusionDetection: intrusionDetectionMode is null ? null : new FirewallPolicyIntrusionDetection(intrusionDetectionMode)),
        RuleCollectionGroups: ruleCollectionGroups);

    private static FirewallPolicyRuleCollectionGroup CreateGroupWithAllowRule(
        string ruleName,
        string source,
        string destination,
        string[]? destinationPorts = null) => new(
        Id: "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Network/firewallPolicies/fp1/ruleCollectionGroups/rcg1",
        Name: "rcg1",
        Type: "Microsoft.Network/firewallPolicies/ruleCollectionGroups",
        Properties: new FirewallPolicyRuleCollectionGroupProperties(
            Priority: 100,
            RuleCollections:
            [
                new FirewallPolicyRuleCollection(
                    RuleCollectionType: "FirewallPolicyFilterRuleCollection",
                    Name: "rc1",
                    Priority: 100,
                    Action: new FirewallPolicyRuleCollectionAction("Allow"),
                    Rules:
                    [
                        new FirewallPolicyRule(
                            RuleType: "NetworkRule",
                            Name: ruleName,
                            SourceAddresses: [source],
                            DestinationAddresses: [destination],
                            DestinationPorts: destinationPorts,
                            DestinationFqdns: null,
                            TargetFqdns: null,
                            TargetUrls: null,
                            Protocols: ["TCP"])
                    ])
            ]));
}
