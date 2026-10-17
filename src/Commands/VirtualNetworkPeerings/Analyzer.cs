using AzureSecurityAnalyzer.ManagementApi;

namespace AzureSecurityAnalyzer.Commands.VirtualNetworkPeerings;

public class Analyzer
{
    public static Task<IReadOnlyCollection<AnomalyDetectionResult>> Analyze(
        IReadOnlyCollection<VirtualNetwork> virtualNetworks)
    {
        var results = new List<AnomalyDetectionResult>();
        var peerings = virtualNetworks
            .SelectMany(virtualNetwork => (virtualNetwork.Properties.VirtualNetworkPeerings ?? [])
                .Select(peering => (VirtualNetwork: virtualNetwork, Peering: peering)))
            .ToArray();

        foreach (var (virtualNetwork, peering) in peerings)
        {
            if (!MatchesValue(peering.Properties.PeeringState, "Connected"))
            {
                results.Add(new AnomalyDetectionResult(
                    virtualNetwork,
                    peering,
                    $"This peering is in '{peering.Properties.PeeringState ?? "unknown"}' state instead of Connected.",
                    SeverityLevel.High));
            }

            if (!peerings.Any(reversePeering =>
                    MatchesValue(reversePeering.Peering.Properties.RemoteVirtualNetwork?.Id, virtualNetwork.Id) &&
                    MatchesValue(reversePeering.VirtualNetwork.Id, peering.Properties.RemoteVirtualNetwork?.Id)))
            {
                results.Add(new AnomalyDetectionResult(
                    virtualNetwork,
                    peering,
                    "This peering does not have a matching peering in the remote virtual network.",
                    SeverityLevel.High));
            }

            if (peering.Properties.AllowVirtualNetworkAccess != true)
            {
                results.Add(new AnomalyDetectionResult(
                    virtualNetwork,
                    peering,
                    "Allow virtual network access is not enabled for this peering.",
                    SeverityLevel.High));
            }

            if (peering.Properties.AllowForwardedTraffic != true)
            {
                results.Add(new AnomalyDetectionResult(
                    virtualNetwork,
                    peering,
                    "Allow forwarded traffic is not enabled for this peering.",
                    SeverityLevel.Medium));
            }
        }

        return Task.FromResult<IReadOnlyCollection<AnomalyDetectionResult>>(results);
    }

    private static bool MatchesValue(string? value, string? expectedValue) =>
        !string.IsNullOrWhiteSpace(value) &&
        !string.IsNullOrWhiteSpace(expectedValue) &&
        string.Equals(value, expectedValue, StringComparison.OrdinalIgnoreCase);
}

public record AnomalyDetectionResult(
    VirtualNetwork VirtualNetwork,
    VirtualNetworkPeering Peering,
    string IssueDescription,
    SeverityLevel Severity);

public enum SeverityLevel
{
    Medium,
    High
}
