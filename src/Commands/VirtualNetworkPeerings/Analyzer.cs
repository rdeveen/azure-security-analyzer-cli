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

            var remoteVirtualNetworkId = peering.Properties.RemoteVirtualNetwork?.Id;
            if (!peerings.Any(reversePeering =>
                    MatchesValue(reversePeering.Peering.Properties.RemoteVirtualNetwork?.Id, virtualNetwork.Id) &&
                    MatchesValue(reversePeering.VirtualNetwork.Id, remoteVirtualNetworkId)))
            {
                var sourceSubscriptionId = GetSubscriptionId(virtualNetwork.Id);
                var remoteSubscriptionId = GetSubscriptionId(remoteVirtualNetworkId);
                var remoteIsOutsideRetrievedScope = !string.IsNullOrWhiteSpace(remoteVirtualNetworkId) &&
                    (sourceSubscriptionId is null || remoteSubscriptionId is null ||
                     !MatchesValue(sourceSubscriptionId, remoteSubscriptionId)) &&
                    !virtualNetworks.Any(network => MatchesValue(network.Id, remoteVirtualNetworkId));

                results.Add(new AnomalyDetectionResult(
                    virtualNetwork,
                    peering,
                    remoteIsOutsideRetrievedScope
                        ? "The remote virtual network is outside the retrieved subscription scope, so the matching peering could not be verified."
                        : "This peering does not have a matching peering in the remote virtual network.",
                    remoteIsOutsideRetrievedScope ? SeverityLevel.Medium : SeverityLevel.High));
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

    private static string? GetSubscriptionId(string? resourceId)
    {
        var segments = resourceId?.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (segments is null)
        {
            return null;
        }

        for (var index = 0; index < segments.Length - 1; index++)
        {
            if (string.Equals(segments[index], "subscriptions", StringComparison.OrdinalIgnoreCase))
            {
                return segments[index + 1];
            }
        }

        return null;
    }
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
