using AzureSecurityAnalyzer.Commands.NetworkSecurityGroups;
using AzureSecurityAnalyzer.ManagementApi;
using AzureSecurityAnalyzer.RegionsApi;
using Spectre.Console;

namespace AzureSecurityAnalyzer.OutputFormatters;

public class ConsoleOutputFormatter : BaseOutputFormatter
{
    public override Task WriteRegions(Commands.Regions.Settings settings, IReadOnlyCollection<AzureRegion> regions)
    {
        var table = new Table();
        table.Border(TableBorder.Rounded);
        table.AddColumn("Region");
        table.AddColumn("Geography");
        table.AddColumn("Display Name");
        table.AddColumn("Sustainability");
        table.AddColumn("Compliance");

        foreach (var region in regions.OrderBy(a => a.Continent).ThenBy(a => a.GeographyId))
        {
            table.AddRow(
                new Markup(region.Continent),
                new Markup(region.GeographyId),
                new Markup((region.IsOpen ? "[green]" : "[red]") + region.DisplayName + "[/]\n[dim](" + region.Id +
                           ")[/]"),
                new Markup(string.Join(", ", region.SustainabilityIds.OrderBy(a => a))),
                new Markup(string.Join(", ", region.ComplianceIds.OrderBy(a => a))));
        }

        AnsiConsole.Write(table);

        return Task.CompletedTask;
    }

    public override Task WriteAzureFirewalls(Commands.AzureFirewalls.Settings settings, IReadOnlyCollection<FirewallPolicy> firewallPolicies, IReadOnlyCollection<AzureFirewall> azureFirewalls, IReadOnlyDictionary<string, IReadOnlyCollection<FirewallPolicyRuleCollectionGroup>> ruleCollectionGroupsByPolicyId, IReadOnlyCollection<Commands.AzureFirewalls.AnomalyDetectionResult> analysisResults)
    {
        if (firewallPolicies.Count == 0)
        {
            AnsiConsole.MarkupLine("[yellow]No firewall policies found.[/]");

            return Task.CompletedTask;
        }

        var table = new Table();
        table.Border(TableBorder.Rounded);
        table.AddColumn("Policy");
        table.AddColumn("Resource Group");
        table.AddColumn("Attached Firewalls");
        table.AddColumn("IDPS Mode");
        table.AddColumn("Threat Intel");
        table.AddColumn("Rule Collections");

        foreach (var firewallPolicy in firewallPolicies.OrderBy(a => a.GetResourceGroupName()).ThenBy(a => a.Name))
        {
            var attachedFirewalls = azureFirewalls
                .Where(f => string.Equals(f.Properties.FirewallPolicy?.Id, firewallPolicy.Id, StringComparison.OrdinalIgnoreCase))
                .OrderBy(f => f.Name)
                .Select(f => Markup.Escape(f.Name))
                .ToArray();

            var attachedSummary = attachedFirewalls.Length == 0
                ? "[dim](none)[/]"
                : string.Join("\n", attachedFirewalls);

            var ruleCollectionGroups = ruleCollectionGroupsByPolicyId.GetValueOrDefault(firewallPolicy.Id) ?? [];
            var ruleCollections = ruleCollectionGroups
                .SelectMany(g => g.Properties.RuleCollections ?? [])
                .OrderBy(c => c.Priority ?? int.MaxValue)
                .Select(c => $"[dim]{Markup.Escape(c.Name)}[/] ({Markup.Escape(c.Action?.Type ?? c.RuleCollectionType)}, {c.Rules?.Length ?? 0} rules)")
                .ToArray();

            var ruleCollectionSummary = ruleCollections.Length == 0
                ? "[dim](none)[/]"
                : string.Join("\n", ruleCollections);

            table.AddRow(
                new Markup(Markup.Escape(firewallPolicy.Name)),
                new Markup(Markup.Escape(firewallPolicy.GetResourceGroupName())),
                new Markup(attachedSummary),
                new Markup(firewallPolicy.Properties.IntrusionDetection?.Mode is { Length: > 0 } mode ? Markup.Escape(mode) : "[red]Off[/]"),
                new Markup(firewallPolicy.Properties.ThreatIntelMode is { Length: > 0 } threatIntelMode ? Markup.Escape(threatIntelMode) : "[dim](not set)[/]"),
                new Markup(ruleCollectionSummary));

            var firewallPolicyAnalysisResults = analysisResults
                .Where(r => r.FirewallPolicy.Id == firewallPolicy.Id)
                .ToList();

            if (firewallPolicyAnalysisResults.Count > 0)
            {
                var anomalyTable = new Table();
                anomalyTable.Border(TableBorder.Rounded);
                anomalyTable.AddColumn($"[red]{(firewallPolicyAnalysisResults.Count == 1 ? "Anomaly Detected" : "Anomalies Detected")}[/]");
                anomalyTable.AddColumn($"Issue Description [dim]({firewallPolicyAnalysisResults.Count} issue{(firewallPolicyAnalysisResults.Count != 1 ? "s" : "")})[/]");

                foreach (var result in firewallPolicyAnalysisResults)
                {
                    anomalyTable.AddRow(
                        new Markup(result.Severity switch
                        {
                            Commands.AzureFirewalls.SeverityLevel.High => "[red]High[/]",
                            Commands.AzureFirewalls.SeverityLevel.Medium => "[orange1]Medium[/]",
                            Commands.AzureFirewalls.SeverityLevel.Low => "[yellow]Low[/]",
                            _ => "[dim]Unknown[/]"
                        }),
                        new Markup(Markup.Escape(result.IssueDescription)));
                }

                table.AddRow(new Markup(""), new Markup(""), new Markup(""), new Markup(""), new Markup(""), anomalyTable);
            }
        }

        AnsiConsole.Write(table);

        return Task.CompletedTask;
    }

    public override Task WriteNetworkSecurityGroups(Commands.NetworkSecurityGroups.Settings settings, IReadOnlyCollection<NetworkSecurityGroup> networkSecurityGroups, IReadOnlyCollection<Commands.NetworkSecurityGroups.AnomalyDetectionResult> analysisResults)
    {
        if (networkSecurityGroups.Count == 0)
        {
            AnsiConsole.MarkupLine("[yellow]No network security groups found.[/]");

            return Task.CompletedTask;
        }

        var table = new Table();
        table.Border(TableBorder.Rounded);
        table.AddColumn("Name");
        table.AddColumn("Resource Group");
        table.AddColumn("Attached");
        table.AddColumn("Security Rules (Priority Access Direction Protocol Source:Port -> Destination:Port)");

        foreach (var nsg in networkSecurityGroups.OrderBy(a => a.GetResourceGroupName()).ThenBy(a => a.Name))
        {
            var attached = nsg.GetAttachedNames();
            var attachedSummary = attached.Length == 0
                ? "[dim](none)[/]"
                : string.Join("\n", attached);

            var rules = nsg.Properties.SecurityRules ?? [];
            var ruleSummary = rules.Length == 0
                ? "[dim](none)[/]"
                : string.Join("\n", rules
                    .OrderBy(r => string.Equals(r.Properties.Direction, "Inbound", StringComparison.OrdinalIgnoreCase)
                        ? 0
                        : string.Equals(r.Properties.Direction, "Outbound", StringComparison.OrdinalIgnoreCase)
                            ? 1
                            : 2)
                    .ThenBy(r => r.Properties.Priority)
                    .Select(r =>
                        $"{r.Properties.Priority} " +
                        (string.Equals(r.Properties.Access, "Allow", StringComparison.OrdinalIgnoreCase) ? "[green]" : "[red]") +
                        $"{r.Properties.Access}[/] {r.Properties.Direction} {r.Properties.Protocol} " +
                        $"{r.Properties.GetValue(r.Properties.SourceAddressPrefix, r.Properties.SourceAddressPrefixes)}:" +
                        $"{r.Properties.GetValue(r.Properties.SourcePortRange, r.Properties.SourcePortRanges)} -> " +
                        $"{r.Properties.GetValue(r.Properties.DestinationAddressPrefix, r.Properties.DestinationAddressPrefixes)}:" +
                        $"{r.Properties.GetValue(r.Properties.DestinationPortRange, r.Properties.DestinationPortRanges)} [dim]({r.Name})[/]"));

            table.AddRow(
                new Markup(nsg.Name),
                new Markup(nsg.GetResourceGroupName()),
                new Markup(attachedSummary),
                new Markup(ruleSummary));

            var nsgAnalysisResults = analysisResults
                .Where(r => r.NetworkSecurityGroup.Id == nsg.Id)
                .ToList();

            if (nsgAnalysisResults.Count > 0)
            {
                var anomalyTable = new Table();
                anomalyTable.Border(TableBorder.Rounded);
                anomalyTable.AddColumn($"[red]{(nsgAnalysisResults.Count == 1 ? "Anomaly Detected" : "Anomalies Detected")}[/]");
                anomalyTable.AddColumn($"Issue Description [dim]({nsgAnalysisResults.Count} issue{(nsgAnalysisResults.Count != 1 ? "s" : "")})[/]");

                foreach (var result in nsgAnalysisResults)
                {
                    anomalyTable.AddRow(
                        new Markup(result.Severity switch
                        {
                            SeverityLevel.High => "[red]High[/]",
                            SeverityLevel.Medium => "[orange1]Medium[/]",
                            SeverityLevel.Low => "[yellow]Low[/]",
                            _ => "[dim]Unknown[/]"
                        }),
                        new Markup(result.IssueDescription)
                    );
                }

                table.AddRow(new Markup(""), new Markup(""), new Markup(""), anomalyTable);
            }
        }

        AnsiConsole.Write(table);

        return Task.CompletedTask;
    }

    public override Task WriteRouteTables(Commands.RouteTables.Settings settings, IReadOnlyCollection<RouteTable> routeTables, IReadOnlyCollection<Commands.RouteTables.AnomalyDetectionResult> analysisResults)
    {
        if (routeTables.Count == 0)
        {
            AnsiConsole.MarkupLine("[yellow]No route tables found.[/]");

            return Task.CompletedTask;
        }

        var table = new Table();
        table.Border(TableBorder.Rounded);
        table.AddColumn("Name");
        table.AddColumn("Resource Group");
        table.AddColumn("Subnets");
        table.AddColumn("BGP Route Propagation");
        table.AddColumn("Routes (Name AddressPrefix NextHopType NextHopIpAddress)");

        foreach (var routeTable in routeTables.OrderBy(a => a.GetResourceGroupName()).ThenBy(a => a.Name))
        {
            var subnets = routeTable.GetAttachedSubnetNames();
            var subnetSummary = subnets.Length == 0
                ? "[dim](none)[/]"
                : string.Join("\n", subnets);

            var bgpPropagation = routeTable.Properties.DisableBgpRoutePropagation == true
                ? "[red]Disabled[/]"
                : "[green]Enabled[/]";

            var routes = routeTable.Properties.Routes ?? [];
            var routeSummary = routes.Length == 0
                ? "[dim](none)[/]"
                : string.Join("\n", routes
                    .OrderBy(r => r.Name)
                    .Select(r =>
                        $"[dim]{r.Name}[/] {r.Properties.AddressPrefix} {r.Properties.NextHopType}" +
                        (string.IsNullOrEmpty(r.Properties.NextHopIpAddress) ? "" : $" -> {r.Properties.NextHopIpAddress}")));

            table.AddRow(
                new Markup(routeTable.Name),
                new Markup(routeTable.GetResourceGroupName()),
                new Markup(subnetSummary),
                new Markup(bgpPropagation),
                new Markup(routeSummary));

            var routeTableAnalysisResults = analysisResults
                .Where(r => r.RouteTable.Id == routeTable.Id)
                .ToList();

            if (routeTableAnalysisResults.Count > 0)
            {
                var anomalyTable = new Table();
                anomalyTable.Border(TableBorder.Rounded);
                anomalyTable.AddColumn($"[red]{(routeTableAnalysisResults.Count == 1 ? "Anomaly Detected" : "Anomalies Detected")}[/]");
                anomalyTable.AddColumn($"Issue Description [dim]({routeTableAnalysisResults.Count} issue{(routeTableAnalysisResults.Count != 1 ? "s" : "")})[/]");

                foreach (var result in routeTableAnalysisResults)
                {
                    anomalyTable.AddRow(
                        new Markup(result.Severity switch
                        {
                            Commands.RouteTables.SeverityLevel.High => "[red]High[/]",
                            Commands.RouteTables.SeverityLevel.Medium => "[orange1]Medium[/]",
                            Commands.RouteTables.SeverityLevel.Low => "[yellow]Low[/]",
                            _ => "[dim]Unknown[/]"
                        }),
                        new Markup(result.IssueDescription)
                    );
                }

                table.AddRow(new Markup(""), new Markup(""), new Markup(""), new Markup(""), anomalyTable);
            }
        }

        AnsiConsole.Write(table);

        return Task.CompletedTask;
    }

    public override Task WriteFirewallPolicies(Commands.Firewall.Settings settings, IReadOnlyCollection<FirewallPolicy> firewallPolicies, IReadOnlyCollection<Commands.Firewall.AnomalyDetectionResult> analysisResults)
    {
        if (firewallPolicies.Count == 0)
        {
            AnsiConsole.MarkupLine("[yellow]No firewall policies found.[/]");

            return Task.CompletedTask;
        }

        var table = new Table();
        table.Border(TableBorder.Rounded);
        table.AddColumn("Name");
        table.AddColumn("Resource Group");
        table.AddColumn("SKU");
        table.AddColumn("Attached Firewalls");
        table.AddColumn("Rule Collection Groups");

        foreach (var policy in firewallPolicies.OrderBy(a => a.GetResourceGroupName()).ThenBy(a => a.Name))
        {
            var firewalls = policy.GetAttachedFirewallNames();
            var firewallSummary = firewalls.Length == 0
                ? "[dim](none)[/]"
                : string.Join("\n", firewalls);

            var groups = policy.RuleCollectionGroups ?? [];
            var groupSummary = groups.Length == 0
                ? "[dim](none)[/]"
                : string.Join("\n", groups
                    .OrderBy(g => g.Properties.Priority)
                    .Select(g =>
                    {
                        var ruleCount = (g.Properties.RuleCollections ?? []).Sum(rc => (rc.Rules ?? []).Length);
                        return $"[dim]{g.Name}[/] ({ruleCount} rule{(ruleCount != 1 ? "s" : "")})";
                    }));

            table.AddRow(
                new Markup(policy.Name),
                new Markup(policy.GetResourceGroupName()),
                new Markup(policy.Sku?.Tier ?? "[dim](none)[/]"),
                new Markup(firewallSummary),
                new Markup(groupSummary));

            var policyAnalysisResults = analysisResults
                .Where(r => r.FirewallPolicy.Id == policy.Id)
                .ToList();

            if (policyAnalysisResults.Count > 0)
            {
                var anomalyTable = new Table();
                anomalyTable.Border(TableBorder.Rounded);
                anomalyTable.AddColumn($"[red]{(policyAnalysisResults.Count == 1 ? "Anomaly Detected" : "Anomalies Detected")}[/]");
                anomalyTable.AddColumn($"Issue Description [dim]({policyAnalysisResults.Count} issue{(policyAnalysisResults.Count != 1 ? "s" : "")})[/]");

                foreach (var result in policyAnalysisResults)
                {
                    anomalyTable.AddRow(
                        new Markup(result.Severity switch
                        {
                            Commands.Firewall.SeverityLevel.High => "[red]High[/]",
                            Commands.Firewall.SeverityLevel.Medium => "[orange1]Medium[/]",
                            Commands.Firewall.SeverityLevel.Low => "[yellow]Low[/]",
                            _ => "[dim]Unknown[/]"
                        }),
                        new Markup(Markup.Escape(result.IssueDescription))
                    );
                }

                table.AddRow(new Markup(""), new Markup(""), new Markup(""), new Markup(""), anomalyTable);
            }
        }

        AnsiConsole.Write(table);

        return Task.CompletedTask;
    }

    public override Task WriteAdvisorRecommendations(Commands.AdvisorRecommendations.Settings settings, IReadOnlyCollection<AdvisorRecommendation> recommendations)
    {
        if (recommendations.Count == 0)
        {
            AnsiConsole.MarkupLine("[yellow]No recommendations found.[/]");

            return Task.CompletedTask;
        }

        var table = new Table();
        table.Border(TableBorder.Rounded);
        table.AddColumn("Category");
        table.AddColumn("Impact");
        table.AddColumn("Impacted Resource");
        table.AddColumn("Problem");
        table.AddColumn("Solution");

        foreach (var recommendation in recommendations
                     .OrderBy(r => r.Properties.Category)
                     .ThenBy(r => r.GetImpactOrder())
                     .ThenBy(r => r.Properties.ImpactedValue))
        {
            var impactColor = recommendation.Properties.Impact switch
            {
                "High" => "[red]",
                "Medium" => "[yellow]",
                _ => "[green]"
            };

            table.AddRow(
                new Markup(recommendation.Properties.Category),
                new Markup($"{impactColor}{recommendation.Properties.Impact}[/]"),
                new Markup(Markup.Escape(recommendation.Properties.ImpactedValue ?? string.Empty) +
                           $"\n[dim]({Markup.Escape(recommendation.Properties.ImpactedField ?? string.Empty)})[/]"),
                new Markup(Markup.Escape(recommendation.Properties.ShortDescription?.Problem ?? string.Empty)),
                new Markup(Markup.Escape(recommendation.Properties.ShortDescription?.Solution ?? string.Empty)));
        }

        AnsiConsole.Write(table);

        return Task.CompletedTask;
    }
}