using AzureSecurityAnalyzer.ManagementApi;

namespace AzureSecurityAnalyzer.Commands.AzureFirewalls;

public class Analyzer
{
    private static readonly IReadOnlyCollection<IFirewallPolicyAnomalyRule> Rules =
    [
        new IntrusionDetectionDisabledRule(),
        new UnusedFirewallPolicyRule(),
        new MissingRuleCollectionsRule(),
        new AllowAllRulesRule()
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
                var detections = rule.TryDetect(firewallPolicy, azureFirewalls, ruleCollectionGroups);
                if (detections.Count > 0)
                {
                    results.AddRange(detections);
                }
            }
        }

        return Task.FromResult<IReadOnlyCollection<AnomalyDetectionResult>>(results);
    }

    private interface IFirewallPolicyAnomalyRule
    {
        IReadOnlyCollection<AnomalyDetectionResult> TryDetect(
            FirewallPolicy firewallPolicy,
            IReadOnlyCollection<AzureFirewall> azureFirewalls,
            IReadOnlyCollection<FirewallPolicyRuleCollectionGroup> ruleCollectionGroups);
    }

    private sealed class IntrusionDetectionDisabledRule : IFirewallPolicyAnomalyRule
    {
        public IReadOnlyCollection<AnomalyDetectionResult> TryDetect(FirewallPolicy firewallPolicy, IReadOnlyCollection<AzureFirewall> azureFirewalls, IReadOnlyCollection<FirewallPolicyRuleCollectionGroup> ruleCollectionGroups)
        {
            if (string.Equals(firewallPolicy.Properties.IntrusionDetection?.Mode, "Off", StringComparison.OrdinalIgnoreCase)
                || string.IsNullOrWhiteSpace(firewallPolicy.Properties.IntrusionDetection?.Mode))
            {
                return
                [
                    new AnomalyDetectionResult(
                    firewallPolicy,
                    "This Firewall Policy does not have intrusion detection configured in alert or deny mode.",
                    SeverityLevel.High)
                ];
            }

            return [];
        }
    }

    private sealed class UnusedFirewallPolicyRule : IFirewallPolicyAnomalyRule
    {
        public IReadOnlyCollection<AnomalyDetectionResult> TryDetect(FirewallPolicy firewallPolicy, IReadOnlyCollection<AzureFirewall> azureFirewalls, IReadOnlyCollection<FirewallPolicyRuleCollectionGroup> ruleCollectionGroups)
        {
            if (!azureFirewalls.Any(f => string.Equals(f.Properties.FirewallPolicy?.Id, firewallPolicy.Id, StringComparison.OrdinalIgnoreCase)))
            {
                return
                [
                    new AnomalyDetectionResult(
                    firewallPolicy,
                    "This Firewall Policy is not attached to any Azure Firewall.",
                    SeverityLevel.Medium)
                ];
            }

            return [];
        }
    }

    private sealed class MissingRuleCollectionsRule : IFirewallPolicyAnomalyRule
    {
        public IReadOnlyCollection<AnomalyDetectionResult> TryDetect(FirewallPolicy firewallPolicy, IReadOnlyCollection<AzureFirewall> azureFirewalls, IReadOnlyCollection<FirewallPolicyRuleCollectionGroup> ruleCollectionGroups)
        {
            if (!ruleCollectionGroups.Any(g => g.Properties.RuleCollections?.Any(c => c.Rules is { Length: > 0 }) == true))
            {
                return
                [
                    new AnomalyDetectionResult(
                    firewallPolicy,
                    "This Firewall Policy does not contain any rules.",
                    SeverityLevel.High)
                ];
            }

            return [];
        }
    }

    private sealed class AllowAllRulesRule : IFirewallPolicyAnomalyRule
    {
        public IReadOnlyCollection<AnomalyDetectionResult> TryDetect(FirewallPolicy firewallPolicy, IReadOnlyCollection<AzureFirewall> azureFirewalls, IReadOnlyCollection<FirewallPolicyRuleCollectionGroup> ruleCollectionGroups)
        {
            return FindAllowAllRules(ruleCollectionGroups)
                .Select(r => new AnomalyDetectionResult(
                    firewallPolicy,
                    $"This Firewall Policy contains an allow-all rule '{r.RuleName}' in rule collection '{r.RuleCollectionName}'.",
                    SeverityLevel.High))
                .ToArray();
        }
    }

    private static IReadOnlyCollection<(string RuleCollectionName, string RuleName)> FindAllowAllRules(IReadOnlyCollection<FirewallPolicyRuleCollectionGroup> ruleCollectionGroups)
    {
        var matchingRules = new List<(string RuleCollectionName, string RuleName)>();
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
                        matchingRules.Add((ruleCollection.Name, rule.Name));
                    }
                }
            }
        }

        return matchingRules;
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
            || ContainsValue(rule.TargetUrls, "*"));

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
