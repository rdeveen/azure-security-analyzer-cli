using AzureSecurityAnalyzer.ManagementApi;

namespace AzureSecurityAnalyzer.OutputFormatters;

public abstract class BaseOutputFormatter
{
    public abstract Task WriteAzureFirewalls(Commands.AzureFirewalls.Settings settings, IReadOnlyCollection<FirewallPolicy> firewallPolicies, IReadOnlyCollection<AzureFirewall> azureFirewalls, IReadOnlyDictionary<string, IReadOnlyCollection<FirewallPolicyRuleCollectionGroup>> ruleCollectionGroupsByPolicyId, IReadOnlyCollection<Commands.AzureFirewalls.AnomalyDetectionResult> analysisResults);

    public abstract Task WriteNetworkSecurityGroups(Commands.NetworkSecurityGroups.Settings settings, IReadOnlyCollection<NetworkSecurityGroup> networkSecurityGroups, IReadOnlyCollection<Commands.NetworkSecurityGroups.AnomalyDetectionResult> analysisResults);

    public abstract Task WriteRouteTables(Commands.RouteTables.Settings settings, IReadOnlyCollection<RouteTable> routeTables, IReadOnlyCollection<Commands.RouteTables.AnomalyDetectionResult> analysisResults);

    public abstract Task WriteAdvisorRecommendations(Commands.AdvisorRecommendations.Settings settings, IReadOnlyCollection<AdvisorRecommendation> recommendations);
}
