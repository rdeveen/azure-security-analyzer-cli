using AzureSecurityAnalyzer.ManagementApi;

namespace AzureSecurityAnalyzer.OutputFormatters;

public class MarkdownOutputFormatter : BaseOutputFormatter
{
    public override Task WriteAzureFirewalls(Commands.AzureFirewalls.Settings settings, IReadOnlyCollection<FirewallPolicy> firewallPolicies, IReadOnlyCollection<AzureFirewall> azureFirewalls, IReadOnlyDictionary<string, IReadOnlyCollection<FirewallPolicyRuleCollectionGroup>> ruleCollectionGroupsByPolicyId, IReadOnlyCollection<Commands.AzureFirewalls.AnomalyDetectionResult> analysisResults)
    {
        if (firewallPolicies.Count == 0)
        {
            Console.WriteLine("No firewall policies found.");

            return Task.CompletedTask;
        }

        Console.WriteLine("# Azure Firewalls");
        Console.WriteLine();
        Console.WriteLine("|Policy|Resource Group|Attached Firewalls|IDPS Mode|Threat Intel|Rule Collections|");
        Console.WriteLine("|---|---|---|---|---|---|");

        foreach (var firewallPolicy in firewallPolicies.OrderBy(a => a.GetResourceGroupName()).ThenBy(a => a.Name))
        {
            var attachedFirewalls = azureFirewalls
                .Where(f => string.Equals(f.Properties.FirewallPolicy?.Id, firewallPolicy.Id, StringComparison.OrdinalIgnoreCase))
                .OrderBy(f => f.Name)
                .Select(f => EscapeMarkdownCell(f.Name));

            var attachedSummary = attachedFirewalls.Any()
                ? string.Join("<br>", attachedFirewalls)
                : "(none)";

            var ruleCollectionGroups = ruleCollectionGroupsByPolicyId.GetValueOrDefault(firewallPolicy.Id) ?? [];
            var ruleCollections = ruleCollectionGroups
                .SelectMany(g => g.Properties.RuleCollections ?? [])
                .OrderBy(c => c.Priority ?? int.MaxValue)
                .Select(c => $"{EscapeMarkdownCell(c.Name)} ({EscapeMarkdownCell(c.Action?.Type ?? c.RuleCollectionType)}, {c.Rules?.Length ?? 0} rules)");

            var ruleCollectionSummary = ruleCollections.Any()
                ? string.Join("<br>", ruleCollections)
                : "(none)";

            var firewallPolicyAnalysisResults = analysisResults.Where(r => r.FirewallPolicy.Id == firewallPolicy.Id).ToList();
            if (firewallPolicyAnalysisResults.Count > 0)
            {
                ruleCollectionSummary += $"<br><br>**{(firewallPolicyAnalysisResults.Count == 1 ? "Anomaly Detected" : "Anomalies Detected")}**<br>{string.Join("<br>", firewallPolicyAnalysisResults.Select(r => $"- {EscapeMarkdownCell(r.IssueDescription)} ({r.Severity})"))}";
            }

            Console.WriteLine($"|{EscapeMarkdownCell(firewallPolicy.Name)}|{EscapeMarkdownCell(firewallPolicy.GetResourceGroupName())}|{attachedSummary}|{EscapeMarkdownCell(firewallPolicy.Properties.IntrusionDetection?.Mode ?? "Off")}|{EscapeMarkdownCell(firewallPolicy.Properties.ThreatIntelMode ?? "(not set)")}|{ruleCollectionSummary}|");
        }

        return Task.CompletedTask;
    }

    public override Task WriteNetworkSecurityGroups(Commands.NetworkSecurityGroups.Settings settings, IReadOnlyCollection<NetworkSecurityGroup> networkSecurityGroups, IReadOnlyCollection<Commands.NetworkSecurityGroups.AnomalyDetectionResult> analysisResults)
    {
        if (networkSecurityGroups.Count == 0)
        {
            Console.WriteLine("No network security groups found.");

            return Task.CompletedTask;
        }

        Console.WriteLine("# Network Security Groups");
        Console.WriteLine();
        Console.WriteLine("|Name|Resource Group|Attached|Security Rules (Priority Access Direction Protocol Source:Port -> Destination:Port)|");
        Console.WriteLine("|---|---|---|---|");

        foreach (var nsg in networkSecurityGroups.OrderBy(a => a.GetResourceGroupName()).ThenBy(a => a.Name))
        {
            var attached = nsg.GetAttachedNames();
            var attachedSummary = attached.Length == 0
                ? "(none)"
                : string.Join("<br>", attached);

            var rules = nsg.Properties.SecurityRules ?? [];
            var ruleSummary = string.Join("<br>", rules
                .OrderBy(r => string.Equals(r.Properties.Direction, "Inbound", StringComparison.OrdinalIgnoreCase)
                    ? 0
                    : string.Equals(r.Properties.Direction, "Outbound", StringComparison.OrdinalIgnoreCase)
                        ? 1
                        : 2)
                .ThenBy(r => r.Properties.Priority)
                .Select(r => $"{r.Properties.Priority} {r.Properties.Access} {r.Properties.Direction} {r.Properties.Protocol} " +
                             $"{r.Properties.GetValue(r.Properties.SourceAddressPrefix, r.Properties.SourceAddressPrefixes)}:" +
                             $"{r.Properties.GetValue(r.Properties.SourcePortRange, r.Properties.SourcePortRanges)} -> " +
                             $"{r.Properties.GetValue(r.Properties.DestinationAddressPrefix, r.Properties.DestinationAddressPrefixes)}:" +
                             $"{r.Properties.GetValue(r.Properties.DestinationPortRange, r.Properties.DestinationPortRanges)} ({r.Name})"));

            if (analysisResults.Any(r => r.NetworkSecurityGroup.Id == nsg.Id))
            {
                var nsgAnalysisResults = analysisResults.Where(r => r.NetworkSecurityGroup.Id == nsg.Id).ToList();

                ruleSummary += $"<br><br>**{(nsgAnalysisResults.Count == 1 ? "Anomaly Detected" : "Anomalies Detected")}**<br>{string.Join("<br>", nsgAnalysisResults.Select(r => $"- {r.IssueDescription} ({r.Severity})"))}";
            }

            Console.WriteLine($"|{nsg.Name}|{nsg.GetResourceGroupName()}|{attachedSummary}|{ruleSummary}|");
        }

        return Task.CompletedTask;
    }

    public override Task WriteRouteTables(Commands.RouteTables.Settings settings, IReadOnlyCollection<RouteTable> routeTables, IReadOnlyCollection<Commands.RouteTables.AnomalyDetectionResult> analysisResults)
    {
        if (routeTables.Count == 0)
        {
            Console.WriteLine("No route tables found.");

            return Task.CompletedTask;
        }

        Console.WriteLine("# Route Tables");
        Console.WriteLine();
        Console.WriteLine("|Name|Resource Group|Subnets|BGP Route Propagation|Routes (Name AddressPrefix NextHopType NextHopIpAddress)|");
        Console.WriteLine("|---|---|---|---|---|");

        foreach (var routeTable in routeTables.OrderBy(a => a.GetResourceGroupName()).ThenBy(a => a.Name))
        {
            var subnets = routeTable.GetAttachedSubnetNames();
            var subnetSummary = subnets.Length == 0 ? "(none)" : string.Join("<br>", subnets);

            var bgpPropagation = routeTable.Properties.DisableBgpRoutePropagation == true ? "Disabled" : "Enabled";

            var routes = routeTable.Properties.Routes ?? [];
            var routeSummary = routes.Length == 0
                ? "(none)"
                : string.Join("<br>", routes
                    .OrderBy(r => r.Name)
                    .Select(r =>
                        $"{r.Name} {r.Properties.AddressPrefix} {r.Properties.NextHopType}" +
                        (string.IsNullOrEmpty(r.Properties.NextHopIpAddress) ? "" : $" -> {r.Properties.NextHopIpAddress}")));

            var routeTableAnalysisResults = analysisResults.Where(r => r.RouteTable.Id == routeTable.Id).ToList();
            if (routeTableAnalysisResults.Count > 0)
            {
                routeSummary += $"<br><br>**{(routeTableAnalysisResults.Count == 1 ? "Anomaly Detected" : "Anomalies Detected")}**<br>{string.Join("<br>", routeTableAnalysisResults.Select(r => $"- {r.IssueDescription} ({r.Severity})"))}";
            }

            Console.WriteLine($"|{routeTable.Name}|{routeTable.GetResourceGroupName()}|{subnetSummary}|{bgpPropagation}|{routeSummary}|");
        }

        return Task.CompletedTask;
    }

    public override Task WriteAdvisorRecommendations(Commands.AdvisorRecommendations.Settings settings, IReadOnlyCollection<AdvisorRecommendation> recommendations)
    {
        if (recommendations.Count == 0)
        {
            Console.WriteLine("No recommendations found.");

            return Task.CompletedTask;
        }

        Console.WriteLine("# Advisor Recommendations");
        Console.WriteLine();
        Console.WriteLine("|Category|Impact|Impacted Resource|Problem|Solution|");
        Console.WriteLine("|---|---|---|---|---|");

        foreach (var recommendation in recommendations
                     .OrderBy(r => r.Properties.Category)
                     .ThenBy(r => r.GetImpactOrder())
                     .ThenBy(r => r.Properties.ImpactedValue))
        {
            Console.WriteLine(
                $"|{recommendation.Properties.Category}" +
                $"|{recommendation.Properties.Impact}" +
                $"|{recommendation.Properties.ImpactedValue} ({recommendation.Properties.ImpactedField})" +
                $"|{recommendation.Properties.ShortDescription?.Problem}" +
                $"|{recommendation.Properties.ShortDescription?.Solution}|");
        }

        return Task.CompletedTask;
    }

    private static string EscapeMarkdownCell(string? value)
    {
        return (value ?? string.Empty)
            .Replace("|", "\\|", StringComparison.Ordinal)
            .Replace("\r", string.Empty, StringComparison.Ordinal)
            .Replace("\n", "<br>", StringComparison.Ordinal);
    }
}