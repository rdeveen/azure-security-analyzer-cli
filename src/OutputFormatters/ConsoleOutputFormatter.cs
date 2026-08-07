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
        table.AddColumn("Location");
        table.AddColumn("Sustainability");
        table.AddColumn("Compliance");

        foreach (var region in regions.OrderBy(a => a.Continent).ThenBy(a => a.GeographyId))
        {
            table.AddRow(
                new Markup(region.Continent),
                new Markup(region.GeographyId),
                new Markup((region.IsOpen ? "[green]" : "[red]") + region.DisplayName + "[/]\n[dim](" + region.Id +
                           ")[/]"),
                new Markup(region.Location),
                new Markup(string.Join(", ", region.SustainabilityIds.OrderBy(a => a))),
                new Markup(string.Join(", ", region.ComplianceIds.OrderBy(a => a))));
        }

        AnsiConsole.Write(table);

        return Task.CompletedTask;
    }

    public override Task WriteNetworkSecurityGroups(Commands.NetworkSecurityGroups.Settings settings, IReadOnlyCollection<NetworkSecurityGroup> networkSecurityGroups)
    {
        var table = new Table();
        table.Border(TableBorder.Rounded);
        table.AddColumn("Name");
        table.AddColumn("Resource Group");
        table.AddColumn("Location");
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
                new Markup(nsg.Location),
                new Markup(attachedSummary),
                new Markup(ruleSummary));
        }

        AnsiConsole.Write(table);

        return Task.CompletedTask;
    }

    public override Task WriteAdvisorRecommendations(Commands.AdvisorRecommendations.Settings settings, IReadOnlyCollection<AdvisorRecommendation> recommendations)
    {
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