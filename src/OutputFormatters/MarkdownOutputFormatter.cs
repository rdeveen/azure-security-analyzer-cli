using AzureSecurityAnalyzer.Commands.Regions;  
using AzureSecurityAnalyzer.RegionsApi;

namespace AzureSecurityAnalyzer.OutputFormatters;

public class MarkdownOutputFormatter : BaseOutputFormatter
{
    public override Task WriteRegions(Settings settings, IReadOnlyCollection<AzureRegion> regions)
    {
        Console.WriteLine("# Azure Regions");
        Console.WriteLine();
        Console.WriteLine("|Region|Geography|Display Name|Location|");
        Console.WriteLine("|---|---|---|---|");

        foreach (var region in regions.OrderBy(a => a.continent).ThenBy(a => a.geographyId))
        {
            Console.WriteLine($"|{region.continent}|{region.geographyId}|{region.displayName}|{region.location}|");
        }

        return Task.CompletedTask;
    }
}