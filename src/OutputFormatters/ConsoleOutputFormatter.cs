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
                    table.AddRow(new Markup(""), new Markup(""), new Markup(""), new Markup(""), anomalyTable);
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