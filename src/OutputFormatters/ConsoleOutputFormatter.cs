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
}