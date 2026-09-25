using AzureSecurityAnalyzer.ManagementApi;

namespace AzureSecurityAnalyzer.Commands.AzureFirewalls;

public class Analyzer
{
    private static readonly IReadOnlyCollection<IFirewallPolicyAnomalyRule> Rules =
    [
        new IntrusionDetectionDisabledRule(),
        new UnusedFirewallPolicyRule(),
        new MissingRuleCollectionsRule(),
        new AllowAllRule()
    ];

    public static Task<IReadOnlyCollection<AnomalyDetectionResult>> Analyze(
        IReadOnlyCollection<FirewallPolicy> firewallPolicies,
        IReadOnlyCollection<AzureFirewall> azureFirewalls,
        IReadOnlyDictionary<string, IReadOnlyCollection<FirewallPolicyRuleCollectionGroup>> ruleCollectionGroupsByPolicyId)
    {
        var results = new List<AnomalyDetectionResult>();
        foreach (var firewallPolicy in firewallPolicies)
        {
            var ruleCollectionGroups = ruleCollectionGroupsByPolicyId.GetValueOrDefault(firewallPolicy.Id) ?? [];
            foreach (var rule in Rules)
            {
                var detection = rule.TryDetect(firewallPolicy, azureFirewalls, ruleCollectionGroups);
                if (detection is not null)
                {
                    results.Add(detection);
                }
            }
        }

        return Task.FromResult<IReadOnlyCollection<AnomalyDetectionResult>>(results);
    }

    private interface IFirewallPolicyAnomalyRule
    {
        AnomalyDetectionResult? TryDetect(
            FirewallPolicy firewallPolicy,
            IReadOnlyCollection<AzureFirewall> azureFirewalls,
            IReadOnlyCollection<FirewallPolicyRuleCollectionGroup> ruleCollectionGroups);
    }

    private sealed class IntrusionDetectionDisabledRule : IFirewallPolicyAnomalyRule
    {
        public AnomalyDetectionResult? TryDetect(FirewallPolicy firewallPolicy, IReadOnlyCollection<AzureFirewall> azureFirewalls, IReadOnlyCollection<FirewallPolicyRuleCollectionGroup> ruleCollectionGroups)
        {
            if (string.Equals(firewallPolicy.Properties.IntrusionDetection?.Mode, "Off", StringComparison.OrdinalIgnoreCase)
                || string.IsNullOrWhiteSpace(firewallPolicy.Properties.IntrusionDetection?.Mode))
            {
                return new AnomalyDetectionResult(
                    firewallPolicy,
                    "This Firewall Policy does not have intrusion detection configured in alert or deny mode.",
                    SeverityLevel.High);
            }

            return null;
        }
    }

    private sealed class UnusedFirewallPolicyRule : IFirewallPolicyAnomalyRule
    {
        public AnomalyDetectionResult? TryDetect(FirewallPolicy firewallPolicy, IReadOnlyCollection<AzureFirewall> azureFirewalls, IReadOnlyCollection<FirewallPolicyRuleCollectionGroup> ruleCollectionGroups)
        {
            if (!azureFirewalls.Any(f => string.Equals(f.Properties.FirewallPolicy?.Id, firewallPolicy.Id, StringComparison.OrdinalIgnoreCase)))
            {
                return new AnomalyDetectionResult(
                    firewallPolicy,
                    "This Firewall Policy is not attached to any Azure Firewall.",
                    SeverityLevel.Medium);
            }

            return null;
        }
    }

    private sealed class MissingRuleCollectionsRule : IFirewallPolicyAnomalyRule
    {
        public AnomalyDetectionResult? TryDetect(FirewallPolicy firewallPolicy, IReadOnlyCollection<AzureFirewall> azureFirewalls, IReadOnlyCollection<FirewallPolicyRuleCollectionGroup> ruleCollectionGroups)
        {
            if (!ruleCollectionGroups.Any(g => g.Properties.RuleCollections?.Any(c => c.Rules is { Length: > 0 }) == true))
            {
                return new AnomalyDetectionResult(
                    firewallPolicy,
                    "This Firewall Policy does not contain any rules.",
                    SeverityLevel.High);
            }

            return null;
        }
    }

    private sealed class AllowAllRule : IFirewallPolicyAnomalyRule
    {
        public AnomalyDetectionResult? TryDetect(FirewallPolicy firewallPolicy, IReadOnlyCollection<AzureFirewall> azureFirewalls, IReadOnlyCollection<FirewallPolicyRuleCollectionGroup> ruleCollectionGroups)
        {
            var matchingRule = FindAllowAllRule(ruleCollectionGroups);
            if (matchingRule is null)
            {
                return null;
            }

            return new AnomalyDetectionResult(
                firewallPolicy,
                $"This Firewall Policy contains an allow-all rule '{matchingRule.Value.RuleName}' in rule collection '{matchingRule.Value.RuleCollectionName}'.",
                SeverityLevel.High);
        }
    }

    private static (string RuleCollectionName, string RuleName)? FindAllowAllRule(IReadOnlyCollection<FirewallPolicyRuleCollectionGroup> ruleCollectionGroups)
    {
        foreach (var ruleCollectionGroup in ruleCollectionGroups)
        {
            var ruleCollections = ruleCollectionGroup.Properties.RuleCollections ?? [];
            foreach (var ruleCollection in ruleCollections)
            {
                if (!string.Equals(ruleCollection.Action?.Type, "Allow", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                foreach (var rule in ruleCollection.Rules ?? [])
                {
                    if (IsAllowAllRule(rule))
                    {
                        return (ruleCollection.Name, rule.Name);
                    }
                }
            }
        }

        return null;
    }

    private static bool IsAllowAllRule(FirewallPolicyRule rule) =>
        IsAllowAllNetworkRule(rule) || IsAllowAllApplicationRule(rule);

    private static bool IsAllowAllNetworkRule(FirewallPolicyRule rule) =>
        string.Equals(rule.RuleType, "NetworkRule", StringComparison.OrdinalIgnoreCase)
        && ContainsValue(rule.SourceAddresses, "*")
        && ContainsValue(rule.DestinationAddresses, "*")
        && ContainsValue(rule.DestinationPorts, "*");

    private static bool IsAllowAllApplicationRule(FirewallPolicyRule rule) =>
        string.Equals(rule.RuleType, "ApplicationRule", StringComparison.OrdinalIgnoreCase)
        && ContainsValue(rule.SourceAddresses, "*")
        && (ContainsValue(rule.TargetFqdns, "*")
            || ContainsValue(rule.TargetUrls, "*")
            || ContainsValue(rule.DestinationAddresses, "*"));

    private static bool ContainsValue(string[]? values, string expectedValue) =>
        values?.Any(v => string.Equals(v, expectedValue, StringComparison.OrdinalIgnoreCase)) ?? false;
}

public record AnomalyDetectionResult(
    FirewallPolicy FirewallPolicy,
    string IssueDescription,
    SeverityLevel Severity);

public enum SeverityLevel
{
    Low,
    Medium,
    High
}
