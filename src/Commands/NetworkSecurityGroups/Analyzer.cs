using AzureSecurityAnalyzer.ManagementApi;

namespace AzureSecurityAnalyzer.Commands.NetworkSecurityGroups;

public class Analyzer
{
    private static readonly IReadOnlyCollection<INetworkSecurityGroupAnomalyRule> Rules =
    [
        new MissingSecurityRulesRule(),
        new ConflictingSecurityRulesRule(),
        new NoDenySecurityRulesRule(),
        new AllowsAllTrafficRule(),
        new AllowsInternetInboundCommonPortsRule(),
        new AllowsInternetInboundAllPortsRule(),
        new AllowsInternetOutboundAllPortsRule(),
        new NotAttachedToSubnetOrNetworkInterfaceRule()
    ];

    public static Task<IReadOnlyCollection<AnomalyDetectionResult>> Analyze(IReadOnlyCollection<NetworkSecurityGroup> networkSecurityGroups)
    {
        var results = new List<AnomalyDetectionResult>();
        foreach (var nsg in networkSecurityGroups)
        {
            foreach (var rule in Rules)
            {
                var detection = rule.TryDetect(nsg);
                if (detection is not null)
                {
                    results.Add(detection);
                }
            }
        }
        return Task.FromResult<IReadOnlyCollection<AnomalyDetectionResult>>(results);
    }

    private interface INetworkSecurityGroupAnomalyRule
    {
        AnomalyDetectionResult? TryDetect(NetworkSecurityGroup networkSecurityGroup);
    }

    private sealed class MissingSecurityRulesRule : INetworkSecurityGroupAnomalyRule
    {
        public AnomalyDetectionResult? TryDetect(NetworkSecurityGroup networkSecurityGroup)
        {
            if (networkSecurityGroup.Properties.SecurityRules == null || networkSecurityGroup.Properties.SecurityRules.Length == 0)
            {
                return new AnomalyDetectionResult(
                    networkSecurityGroup,
                    "This Network Security Group has no security rules defined.",
                    SeverityLevel.High);
            }

            return null;
        }
    }

    private sealed class AllowsAllTrafficRule : INetworkSecurityGroupAnomalyRule
    {
        public AnomalyDetectionResult? TryDetect(NetworkSecurityGroup networkSecurityGroup)
        {
            if (HasAnySecurityRule(networkSecurityGroup, r =>
                IsAllowInbound(r) &&
                IsAnySourceAddress(r) &&
                IsAnyDestinationAddress(r) &&
                IsAnySourcePort(r) &&
                IsAnyDestinationPort(r))
                &&
                HasAnySecurityRule(networkSecurityGroup, r =>
                IsAllowOutbound(r) &&
                IsAnySourceAddress(r) &&
                IsAnyDestinationAddress(r) &&
                IsAnySourcePort(r) &&
                IsAnyDestinationPort(r))
                &&
                networkSecurityGroup.Properties.SecurityRules?.Length == 2)
            {
                return new AnomalyDetectionResult(
                    networkSecurityGroup,
                    "This Network Security Group has security rules that allow all inbound and all outbound traffic.",
                    SeverityLevel.High);
            }

            return null;
        }
    }

    private sealed class ConflictingSecurityRulesRule : INetworkSecurityGroupAnomalyRule
    {
        public AnomalyDetectionResult? TryDetect(NetworkSecurityGroup networkSecurityGroup)
        {
            var securityRules = networkSecurityGroup.Properties.SecurityRules?.OrderBy(r => r.Properties.Priority).ToArray();
            if (securityRules is not { Length: > 1 })
            {
                return null;
            }

            for (var i = 0; i < securityRules.Length - 1; i++)
            {
                for (var j = i + 1; j < securityRules.Length; j++)
                {
                    var rule1 = securityRules[i];
                    var rule2 = securityRules[j];

                    if (MatchesValue(rule1.Id, rule2.Id))
                    {
                        continue;
                    }

                    if (IsConflictingRulePair(rule1, rule2))
                    {
                        return new AnomalyDetectionResult(
                            networkSecurityGroup,
                            $"This Network Security Group has conflicting security rules: '{rule1.Name}' and '{rule2.Name}'.",
                            SeverityLevel.Low);
                    }
                }
            }

            return null;
        }
    }

    private sealed class NoDenySecurityRulesRule : INetworkSecurityGroupAnomalyRule
    {
        public AnomalyDetectionResult? TryDetect(NetworkSecurityGroup networkSecurityGroup)
        {
            var securityRules = networkSecurityGroup.Properties.SecurityRules;
            if (securityRules is { Length: > 0 } && !securityRules.Any(IsDenyRule))
            {
                return new AnomalyDetectionResult(
                    networkSecurityGroup,
                    "This Network Security Group has no deny security rules defined.",
                    SeverityLevel.Medium);
            }

            return null;
        }
    }

    private sealed class AllowsInternetInboundCommonPortsRule : INetworkSecurityGroupAnomalyRule
    {
        public AnomalyDetectionResult? TryDetect(NetworkSecurityGroup networkSecurityGroup)
        {
            if (HasAnySecurityRule(networkSecurityGroup, r =>
                IsAllowInbound(r) &&
                IsAnySourceAddress(r) &&
                (MatchesValue(r.Properties.DestinationPortRange, "22") ||
                 ContainsValue(r.Properties.DestinationPortRanges, "22") ||
                 MatchesValue(r.Properties.DestinationPortRange, "3389") ||
                 ContainsValue(r.Properties.DestinationPortRanges, "3389"))))
            {
                return new AnomalyDetectionResult(
                    networkSecurityGroup,
                    "This Network Security Group has security rules that allow inbound traffic from the internet on common ports (e.g., 22, 3389).",
                    SeverityLevel.High);
            }

            return null;
        }
    }

    private sealed class AllowsInternetInboundAllPortsRule : INetworkSecurityGroupAnomalyRule
    {
        public AnomalyDetectionResult? TryDetect(NetworkSecurityGroup networkSecurityGroup)
        {
            if (HasAnySecurityRule(networkSecurityGroup, r =>
                IsAllowInbound(r) &&
                IsAnySourceAddress(r) &&
                IsAnyDestinationPort(r)))
            {
                return new AnomalyDetectionResult(
                    networkSecurityGroup,
                    "This Network Security Group has security rules that allow inbound traffic from the internet on all ports.",
                    SeverityLevel.High);
            }

            return null;
        }
    }

    private sealed class AllowsInternetOutboundAllPortsRule : INetworkSecurityGroupAnomalyRule
    {
        public AnomalyDetectionResult? TryDetect(NetworkSecurityGroup networkSecurityGroup)
        {
            if (HasAnySecurityRule(networkSecurityGroup, r =>
                IsAllowOutbound(r) &&
                IsAnySourceAddress(r) &&
                IsAnyDestinationPort(r)))
            {
                return new AnomalyDetectionResult(
                    networkSecurityGroup,
                    "This Network Security Group has security rules that allow outbound traffic to the internet on all ports.",
                    SeverityLevel.Medium);
            }

            return null;
        }
    }

    private sealed class NotAttachedToSubnetOrNetworkInterfaceRule : INetworkSecurityGroupAnomalyRule
    {
        public AnomalyDetectionResult? TryDetect(NetworkSecurityGroup networkSecurityGroup)
        {
            var hasSubnets = networkSecurityGroup.Properties.Subnets is { Length: > 0 };
            var hasNetworkInterfaces = networkSecurityGroup.Properties.NetworkInterfaces is { Length: > 0 };

            if (!hasSubnets && !hasNetworkInterfaces)
            {
                return new AnomalyDetectionResult(
                    networkSecurityGroup,
                    "This Network Security Group is not attached to any subnets or network interfaces. This may give a false sense of security, as it is not actually protecting any resources.",
                    SeverityLevel.Low);
            }

            return null;
        }
    }

    private static bool HasAnySecurityRule(NetworkSecurityGroup networkSecurityGroup, Func<SecurityRule, bool> predicate) =>
        networkSecurityGroup.Properties.SecurityRules?.Any(predicate) ?? false;

    private static bool IsAllowInbound(SecurityRule securityRule) =>
        MatchesValue(securityRule.Properties.Access, "Allow") &&
        MatchesValue(securityRule.Properties.Direction, "Inbound");

    private static bool IsAllowOutbound(SecurityRule securityRule) =>
        MatchesValue(securityRule.Properties.Access, "Allow") &&
        MatchesValue(securityRule.Properties.Direction, "Outbound");

    private static bool IsDenyRule(SecurityRule securityRule) =>
        MatchesValue(securityRule.Properties.Access, "Deny");

    private static bool IsConflictingRulePair(SecurityRule rule1, SecurityRule rule2) =>
        MatchesValue(rule1.Properties.SourceAddressPrefix, rule2.Properties.SourceAddressPrefix)
        && MatchesValue(rule1.Properties.DestinationAddressPrefix, rule2.Properties.DestinationAddressPrefix)
        && MatchesValue(rule1.Properties.DestinationPortRange, rule2.Properties.DestinationPortRange)
        && !MatchesValue(rule1.Properties.Access, rule2.Properties.Access);

    private static bool IsAnySourceAddress(SecurityRule securityRule) =>
        MatchesValue(securityRule.Properties.SourceAddressPrefix, "*") || ContainsValue(securityRule.Properties.SourceAddressPrefixes, "*");

    private static bool IsAnyDestinationAddress(SecurityRule securityRule) =>
        MatchesValue(securityRule.Properties.DestinationAddressPrefix, "*") || ContainsValue(securityRule.Properties.DestinationAddressPrefixes, "*");

    private static bool IsAnySourcePort(SecurityRule securityRule) =>
        MatchesValue(securityRule.Properties.SourcePortRange, "*") || ContainsValue(securityRule.Properties.SourcePortRanges, "*");

    private static bool IsAnyDestinationPort(SecurityRule securityRule) =>
        MatchesValue(securityRule.Properties.DestinationPortRange, "*") || ContainsValue(securityRule.Properties.DestinationPortRanges, "*");

    private static bool MatchesValue(string? value, string? expectedValue) =>
        string.Equals(value, expectedValue, StringComparison.OrdinalIgnoreCase);

    private static bool ContainsValue(string[]? values, string expectedValue) =>
        values?.Any(v => string.Equals(v, expectedValue, StringComparison.OrdinalIgnoreCase)) ?? false;
}

public record AnomalyDetectionResult(
    NetworkSecurityGroup NetworkSecurityGroup,
    string IssueDescription,
    SeverityLevel Severity);

public enum SeverityLevel
{
    Low,
    Medium,
    High
}