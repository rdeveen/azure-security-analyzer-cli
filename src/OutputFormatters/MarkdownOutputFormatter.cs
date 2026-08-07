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

        foreach (var region in regions.OrderBy(a => a.Continent).ThenBy(a => a.GeographyId))
        {
            Console.WriteLine($"|{region.Continent}|{region.GeographyId}|{region.DisplayName}|{region.Location}|");
        }

        return Task.CompletedTask;
    }

    public override Task WriteNetworkSecurityGroups(Commands.NetworkSecurityGroups.Settings settings, IReadOnlyCollection<NetworkSecurityGroup> networkSecurityGroups)
    {
        Console.WriteLine("# Network Security Groups");
        Console.WriteLine();
        Console.WriteLine("|Name|Resource Group|Location|Attached|Security Rules (Priority Access Direction Protocol Source:Port -> Destination:Port)|");
        Console.WriteLine("|---|---|---|---|---|");

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

            Console.WriteLine($"|{nsg.Name}|{nsg.GetResourceGroupName()}|{nsg.Location}|{attachedSummary}|{ruleSummary}|");
        }

        return Task.CompletedTask;
    }
}