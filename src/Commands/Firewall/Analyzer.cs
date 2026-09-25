using AzureSecurityAnalyzer.ManagementApi;

namespace AzureSecurityAnalyzer.Commands.Firewall;

public class Analyzer
{
    private static readonly IReadOnlyCollection<IFirewallPolicyAnomalyRule> Rules =
    [
        new DetectionOnlyModeRule(),
        new PolicyNotAttachedToFirewallRule(),
        new PolicyHasNoRulesRule(),
        new AllowAllRuleRule()
    ];

    public static Task<IReadOnlyCollection<AnomalyDetectionResult>> Analyze(IReadOnlyCollection<FirewallPolicy> firewallPolicies)
    {
        var results = new List<AnomalyDetectionResult>();
        foreach (var firewallPolicy in firewallPolicies)
        {
            foreach (var rule in Rules)
            {
                foreach (var detection in rule.Detect(firewallPolicy))
                {
                    results.Add(detection);
                }
            }
        }

        return Task.FromResult<IReadOnlyCollection<AnomalyDetectionResult>>(results);
    }

    private interface IFirewallPolicyAnomalyRule
    {
        IEnumerable<AnomalyDetectionResult> Detect(FirewallPolicy firewallPolicy);
    }

    private sealed class DetectionOnlyModeRule : IFirewallPolicyAnomalyRule
    {
        public IEnumerable<AnomalyDetectionResult> Detect(FirewallPolicy firewallPolicy)
        {
            // Intrusion detection is only available on Premium SKU; skip otherwise to avoid noise.
            if (!string.Equals(firewallPolicy.Sku?.Tier, "Premium", StringComparison.OrdinalIgnoreCase))
            {
                yield break;
            }

            var mode = firewallPolicy.Properties.IntrusionDetection?.Mode;
            if (string.Equals(mode, "Alert", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(mode, "Off", StringComparison.OrdinalIgnoreCase) ||
                string.IsNullOrWhiteSpace(mode))
            {
                yield return new AnomalyDetectionResult(
                    firewallPolicy,
                    $"This firewall policy has intrusion detection in '{mode ?? "Off"}' mode instead of 'Deny'.",
                    SeverityLevel.Medium);
            }
        }
    }

    private sealed class PolicyNotAttachedToFirewallRule : IFirewallPolicyAnomalyRule
    {
        public IEnumerable<AnomalyDetectionResult> Detect(FirewallPolicy firewallPolicy)
        {
            if (firewallPolicy.Properties.Firewalls is not { Length: > 0 })
            {
                yield return new AnomalyDetectionResult(
                    firewallPolicy,
                    "This firewall policy is not attached to any firewall.",
                    SeverityLevel.Low);
            }
        }
    }

    private sealed class PolicyHasNoRulesRule : IFirewallPolicyAnomalyRule
    {
        public IEnumerable<AnomalyDetectionResult> Detect(FirewallPolicy firewallPolicy)
        {
            var groups = firewallPolicy.RuleCollectionGroups ?? [];
            var hasAnyRules = groups
                .SelectMany(g => g.Properties.RuleCollections ?? [])
                .Any(rc => rc.Rules is { Length: > 0 });

            if (!hasAnyRules)
            {
                yield return new AnomalyDetectionResult(
                    firewallPolicy,
                    "This firewall policy has no rules configured.",
                    SeverityLevel.Medium);
            }
        }
    }

    private sealed class AllowAllRuleRule : IFirewallPolicyAnomalyRule
    {
        public IEnumerable<AnomalyDetectionResult> Detect(FirewallPolicy firewallPolicy)
        {
            var groups = firewallPolicy.RuleCollectionGroups ?? [];
            foreach (var group in groups)
            {
                var collections = group.Properties.RuleCollections ?? [];
                foreach (var collection in collections)
                {
                    if (!string.Equals(collection.Action?.Type, "Allow", StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    var rules = collection.Rules ?? [];
                    foreach (var rule in rules)
                    {
                        if (IsAllowAll(rule))
                        {
                            yield return new AnomalyDetectionResult(
                                firewallPolicy,
                                $"This firewall policy has an allow-all rule '{rule.Name}' in rule collection '{collection.Name}'.",
                                SeverityLevel.High);
                        }
                    }
                }
            }
        }

        private static bool IsAllowAll(FirewallPolicyRule rule) =>
            HasWildcard(rule.SourceAddresses) &&
            (HasWildcard(rule.DestinationAddresses) ||
             HasWildcard(rule.DestinationFqdns) ||
             HasWildcard(rule.TargetFqdns) ||
             HasWildcard(rule.TargetUrls)) &&
            (rule.DestinationPorts is null || HasWildcard(rule.DestinationPorts));

        private static bool HasWildcard(string[]? values)
        {
            if (values is not { Length: > 0 })
            {
                return false;
            }

            return values.Any(v =>
                string.Equals(v, "*", StringComparison.Ordinal) ||
                string.Equals(v, "0.0.0.0/0", StringComparison.Ordinal) ||
                string.Equals(v, "Any", StringComparison.OrdinalIgnoreCase));
        }
    }
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
