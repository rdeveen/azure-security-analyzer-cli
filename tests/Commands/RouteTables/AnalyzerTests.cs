using AzureSecurityAnalyzer.Commands.RouteTables;
using AzureSecurityAnalyzer.ManagementApi;
using AwesomeAssertions;

namespace AzureSecurityAnalyzer.Tests.Commands.RouteTables;

public class AnalyzerTests
{
    [Fact]
    public async Task Analyze_WithDefaultRouteToFirewall_ReturnsNoDefaultRouteAnomaly()
    {
        // Arrange
        var routeTable = CreateRouteTable(
            routes:
            [
                CreateRoute(
                    name: "defaultToFirewall",
                    addressPrefix: "0.0.0.0/0",
                    nextHopType: "VirtualAppliance",
                    nextHopIpAddress: "10.0.0.4")
            ],
            subnets: [new ResourceReference("/subnets/subnet1")]);

        // Act
        var results = await Analyzer.Analyze([routeTable]);

        // Assert
        results.Should().BeEmpty();
    }

    [Fact]
    public async Task Analyze_WithoutDefaultRouteToFirewall_ReturnsMissingFirewallAnomaly()
    {
        // Arrange
        var routeTable = CreateRouteTable(
            routes:
            [
                CreateRoute(
                    name: "internalRoute",
                    addressPrefix: "10.0.0.0/16",
                    nextHopType: "VirtualAppliance",
                    nextHopIpAddress: "10.0.0.4")
            ],
            subnets: [new ResourceReference("/subnets/subnet1")]);

        // Act
        var results = await Analyzer.Analyze([routeTable]);

        // Assert
        results.Count.Should().Be(1);
        results.Single().IssueDescription.Should().Be("This route table has no default route to a firewall.");
        results.Single().Severity.Should().Be(SeverityLevel.Medium);
    }

    [Fact]
    public async Task Analyze_WithDefaultRouteToInternet_ReturnsInternetNextHopAnomaly()
    {
        // Arrange
        var routeTable = CreateRouteTable(
            routes:
            [
                CreateRoute(
                    name: "defaultToInternet",
                    addressPrefix: "0.0.0.0/0",
                    nextHopType: "Internet")
            ],
            subnets: [new ResourceReference("/subnets/subnet1")]);

        // Act
        var results = await Analyzer.Analyze([routeTable]);

        // Assert
        results.Count.Should().Be(2);
        results.Select(r => r.IssueDescription).Should().Contain("This route table has no default route to a firewall.");
        results.Select(r => r.IssueDescription).Should().Contain("This route table has a default route 'defaultToInternet' with the next hop set directly to the internet.");
    }

    [Fact]
    public async Task Analyze_WithoutAttachedSubnets_ReturnsUnattachedAnomaly()
    {
        // Arrange
        var routeTable = CreateRouteTable(
            routes:
            [
                CreateRoute(
                    name: "defaultToFirewall",
                    addressPrefix: "0.0.0.0/0",
                    nextHopType: "VirtualAppliance",
                    nextHopIpAddress: "10.0.0.4")
            ],
            subnets: null);

        // Act
        var results = await Analyzer.Analyze([routeTable]);

        // Assert
        results.Count.Should().Be(1);
        results.Single().IssueDescription.Should().Be("This route table is not attached to any subnets.");
        results.Single().Severity.Should().Be(SeverityLevel.Low);
    }

    [Fact]
    public async Task Analyze_WhenMultipleRulesMatch_ReturnsAllMatchingAnomalies()
    {
        // Arrange
        var routeTable = CreateRouteTable(
            routes:
            [
                CreateRoute(
                    name: "defaultToInternet",
                    addressPrefix: "0.0.0.0/0",
                    nextHopType: "Internet")
            ],
            subnets: []);

        // Act
        var results = await Analyzer.Analyze([routeTable]);

        // Assert
        results.Count.Should().Be(3);
        var descriptions = results.Select(r => r.IssueDescription).ToArray();
        descriptions.Should().Contain("This route table has no default route to a firewall.");
        descriptions.Should().Contain("This route table has a default route 'defaultToInternet' with the next hop set directly to the internet.");
        descriptions.Should().Contain("This route table is not attached to any subnets.");
    }

    private static RouteTable CreateRouteTable(Route[]? routes, ResourceReference[]? subnets) => new(
        Id: "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Network/routeTables/rt1",
        Name: "rt1",
        Type: "Microsoft.Network/routeTables",
        Location: "westeurope",
        Tags: null,
        Properties: new RouteTableProperties(
            ProvisioningState: "Succeeded",
            Routes: routes,
            Subnets: subnets,
            DisableBgpRoutePropagation: false));

    private static Route CreateRoute(
        string name,
        string addressPrefix,
        string nextHopType,
        string? nextHopIpAddress = null) => new(
            Id: $"/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Network/routeTables/rt1/routes/{name}",
            Name: name,
            Type: "Microsoft.Network/routeTables/routes",
            Properties: new RouteProperties(
                ProvisioningState: "Succeeded",
                AddressPrefix: addressPrefix,
                NextHopType: nextHopType,
                NextHopIpAddress: nextHopIpAddress));
}
