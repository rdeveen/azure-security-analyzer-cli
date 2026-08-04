using AzureSecurityAnalyzer.Commands.Regions;
using AzureSecurityAnalyzer.ManagementApi;
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

    public override Task WriteNetworkSecurityGroups(Commands.NetworkSecurityGroups.Settings settings, IReadOnlyCollection<NetworkSecurityGroup> networkSecurityGroups)
    {
        Console.WriteLine("# Network Security Groups");
        Console.WriteLine();
        Console.WriteLine("|Name|Resource Group|Location|Security Rules (Priority Access Direction Protocol Source:Port -> Destination:Port)|");
        Console.WriteLine("|---|---|---|---|");

        foreach (var nsg in networkSecurityGroups.OrderBy(a => GetResourceGroupName(a.id)).ThenBy(a => a.name))
        {
            var rules = nsg.properties.securityRules ?? [];
            var ruleSummary = string.Join("<br>", rules
                .OrderBy(r => string.Equals(r.properties.direction, "Inbound", StringComparison.OrdinalIgnoreCase)
                    ? 0
                    : string.Equals(r.properties.direction, "Outbound", StringComparison.OrdinalIgnoreCase)
                        ? 1
                        : 2)
                .ThenBy(r => r.properties.priority)
                .Select(r => $"{r.properties.priority} {r.properties.access} {r.properties.direction} {r.properties.protocol} " +
                             $"{r.properties.GetValue(r.properties.sourceAddressPrefix, r.properties.sourceAddressPrefixes)}:" +
                             $"{r.properties.GetValue(r.properties.sourcePortRange, r.properties.sourcePortRanges)} -> " +
                             $"{r.properties.GetValue(r.properties.destinationAddressPrefix, r.properties.destinationAddressPrefixes)}:" +
                             $"{r.properties.GetValue(r.properties.destinationPortRange, r.properties.destinationPortRanges)} ({r.name})"));

            Console.WriteLine($"|{nsg.name}|{GetResourceGroupName(nsg.id)}|{nsg.location}|{ruleSummary}|");
        }

        return Task.CompletedTask;
    }
}