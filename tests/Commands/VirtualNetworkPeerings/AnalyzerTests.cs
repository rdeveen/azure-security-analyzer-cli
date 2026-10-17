using AzureSecurityAnalyzer.Commands.VirtualNetworkPeerings;
using AzureSecurityAnalyzer.ManagementApi;
using AwesomeAssertions;

namespace AzureSecurityAnalyzer.Tests.Commands.VirtualNetworkPeerings;

public class AnalyzerTests
{
    [Fact]
    public async Task Analyze_WithHealthyBidirectionalPeerings_ReturnsNoAnomalies()
    {
        var virtualNetworks = new[]
        {
            CreateVirtualNetwork("vnet-a",
                CreatePeering("vnet-a-to-b", GetVirtualNetworkId("vnet-b"))),
            CreateVirtualNetwork("vnet-b",
                CreatePeering("vnet-b-to-a", GetVirtualNetworkId("vnet-a")))
        };

        var results = await Analyzer.Analyze(virtualNetworks);

        results.Should().BeEmpty();
    }

    [Fact]
    public async Task Analyze_WithUnhealthyOneWayPeering_ReportsEveryRequirement()
    {
        var virtualNetworks = new[]
        {
            CreateVirtualNetwork("vnet-a",
                CreatePeering(
                    "vnet-a-to-b",
                    GetVirtualNetworkId("vnet-b"),
                    peeringState: "Initiated",
                    allowVirtualNetworkAccess: false,
                    allowForwardedTraffic: false))
        };

        var results = await Analyzer.Analyze(virtualNetworks);

        results.Should().HaveCount(4);
        results.Select(result => result.IssueDescription).Should().Contain([
            "This peering is in 'Initiated' state instead of Connected.",
            "This peering does not have a matching peering in the remote virtual network.",
            "Allow virtual network access is not enabled for this peering.",
            "Allow forwarded traffic is not enabled for this peering."
        ]);
    }

    [Fact]
    public async Task Analyze_WithOneWayPeering_ReportsMissingReversePeering()
    {
        var virtualNetworks = new[]
        {
            CreateVirtualNetwork("vnet-a",
                CreatePeering("vnet-a-to-b", GetVirtualNetworkId("vnet-b")))
        };

        var results = await Analyzer.Analyze(virtualNetworks);

        results.Should().ContainSingle(result =>
            result.IssueDescription == "This peering does not have a matching peering in the remote virtual network.");
    }

    [Fact]
    public async Task Analyze_WithCrossSubscriptionRemoteVirtualNetworkOutsideRetrievedScope_ReportsVerificationUnavailable()
    {
        var virtualNetworks = new[]
        {
            CreateVirtualNetwork("vnet-a",
                CreatePeering("vnet-a-to-b", GetVirtualNetworkId("vnet-b", "sub2")))
        };

        var results = await Analyzer.Analyze(virtualNetworks);

        results.Should().ContainSingle(result =>
            result.IssueDescription == "The remote virtual network could not be retrieved, so the matching peering could not be verified.");
    }

    [Fact]
    public async Task Analyze_WithHealthyCrossSubscriptionPeeringAndRetrievedRemoteVirtualNetwork_ReturnsNoAnomalies()
    {
        var selectedSubscriptionVirtualNetworks = new[]
        {
            CreateVirtualNetwork("vnet-a",
                CreatePeering("vnet-a-to-b", GetVirtualNetworkId("vnet-b", "sub2")))
        };
        var remoteVirtualNetworks = new[]
        {
            CreateVirtualNetwork("vnet-b", "sub2",
                CreatePeering("vnet-b-to-a", GetVirtualNetworkId("vnet-a")))
        };

        var results = await Analyzer.Analyze(selectedSubscriptionVirtualNetworks, remoteVirtualNetworks);

        results.Should().BeEmpty();
    }

    private static VirtualNetwork CreateVirtualNetwork(string name, params VirtualNetworkPeering[] peerings) =>
        CreateVirtualNetwork(name, "sub1", peerings);

    private static VirtualNetwork CreateVirtualNetwork(
        string name,
        string subscriptionId,
        params VirtualNetworkPeering[] peerings) => new(
        Id: GetVirtualNetworkId(name, subscriptionId),
        Name: name,
        Type: "Microsoft.Network/virtualNetworks",
        Location: "westeurope",
        Tags: null,
        Properties: new VirtualNetworkProperties("Succeeded", peerings));

    private static VirtualNetworkPeering CreatePeering(
        string name,
        string remoteVirtualNetworkId,
        string peeringState = "Connected",
        bool allowVirtualNetworkAccess = true,
        bool allowForwardedTraffic = true) => new(
        Id: $"/virtualNetworks/{name}",
        Name: name,
        Type: "Microsoft.Network/virtualNetworks/virtualNetworkPeerings",
        Properties: new VirtualNetworkPeeringProperties(
            PeeringState: peeringState,
            AllowVirtualNetworkAccess: allowVirtualNetworkAccess,
            AllowForwardedTraffic: allowForwardedTraffic,
            RemoteVirtualNetwork: new ResourceReference(remoteVirtualNetworkId)));

    private static string GetVirtualNetworkId(string name) =>
        GetVirtualNetworkId(name, "sub1");

    private static string GetVirtualNetworkId(string name, string subscriptionId) =>
        $"/subscriptions/{subscriptionId}/resourceGroups/rg1/providers/Microsoft.Network/virtualNetworks/{name}";
}
