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

        foreach (var region in regions.OrderBy(a => a.continent).ThenBy(a => a.geographyId))
        {
            table.AddRow(
                new Markup(region.continent),
                new Markup(region.geographyId),
                new Markup((region.isOpen ? "[green]" : "[red]") + region.displayName + "[/]\n[dim](" + region.id +
                           ")[/]"),
                new Markup(region.location),
                new Markup(string.Join(", ", region.sustainabilityIds)),
                new Markup(string.Join(", ", region.complianceIds.OrderBy(a => a))));
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
        table.AddColumn("Security Rules (Priority Access Direction Protocol Source:Port -> Destination:Port)");

        foreach (var nsg in networkSecurityGroups.OrderBy(a => GetResourceGroupName(a.id)).ThenBy(a => a.name))
        {
            var rules = nsg.properties.securityRules ?? [];
            var ruleSummary = rules.Length == 0
                ? "[dim](none)[/]"
                : string.Join("\n", rules
                    .OrderBy(r => string.Equals(r.properties.direction, "Inbound", StringComparison.OrdinalIgnoreCase)
                        ? 0
                        : string.Equals(r.properties.direction, "Outbound", StringComparison.OrdinalIgnoreCase)
                            ? 1
                            : 2)
                    .ThenBy(r => r.properties.priority)
                    .Select(r =>
                        $"{r.properties.priority} " +
                        (string.Equals(r.properties.access, "Allow", StringComparison.OrdinalIgnoreCase) ? "[green]" : "[red]") +
                        $"{r.properties.access}[/] {r.properties.direction} {r.properties.protocol} " +
                        $"{r.properties.GetValue(r.properties.sourceAddressPrefix, r.properties.sourceAddressPrefixes)}:" +
                        $"{r.properties.GetValue(r.properties.sourcePortRange, r.properties.sourcePortRanges)} -> " +
                        $"{r.properties.GetValue(r.properties.destinationAddressPrefix, r.properties.destinationAddressPrefixes)}:" +
                        $"{r.properties.GetValue(r.properties.destinationPortRange, r.properties.destinationPortRanges)} [dim]({r.name})[/]"));

            table.AddRow(
                new Markup(nsg.name),
                new Markup(GetResourceGroupName(nsg.id)),
                new Markup(nsg.location),
                new Markup(ruleSummary));
        }

        AnsiConsole.Write(table);

        return Task.CompletedTask;
    }
}