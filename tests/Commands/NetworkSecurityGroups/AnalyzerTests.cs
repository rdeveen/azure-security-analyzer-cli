using AzureSecurityAnalyzer.Commands.NetworkSecurityGroups;
using AzureSecurityAnalyzer.ManagementApi;
using Shouldly;

namespace AzureSecurityAnalyzer.Tests.Commands.NetworkSecurityGroups;

public class AnalyzerTests
{
    [Fact]
    public async Task Analyze_WithNoSecurityRules_ReturnsMissingRulesAnomaly()
    {
        // Arrange
        var nsg = CreateNetworkSecurityGroup(securityRules: null, subnets: [new ResourceReference("/subnets/s1")]);

        // Act
        var results = await Analyzer.Analyze([nsg]);

        // Assert
        results.Count.ShouldBe(1);
        results.Single().IssueDescription.ShouldBe("This Network Security Group has no security rules defined.");
        results.Single().Severity.ShouldBe(SeverityLevel.Medium);
    }

    [Fact]
    public async Task Analyze_WithAllowAllTrafficRule_ReturnsAllowAllTrafficAnomaly()
    {
        // Arrange
        var nsg = CreateNetworkSecurityGroup(
            securityRules:
            [
                CreateSecurityRule(
                    sourceAddressPrefix: "*",
                    destinationAddressPrefix: "*",
                    sourcePortRange: "*",
                    destinationPortRange: "*")
            ],
            subnets: [new ResourceReference("/subnets/s1")]);

        // Act
        var results = await Analyzer.Analyze([nsg]);

        // Assert
        results.Count.ShouldBe(2);
        results.Select(r => r.IssueDescription).ShouldContain("This Network Security Group has security rules that allow all inbound traffic.");
    }

    [Fact]
    public async Task Analyze_WithInternetInboundOnCommonPorts_ReturnsCommonPortsAnomaly()
    {
        // Arrange
        var nsg = CreateNetworkSecurityGroup(
            securityRules:
            [
                CreateSecurityRule(
                    sourceAddressPrefix: "*",
                    destinationPortRange: "22")
            ],
            subnets: [new ResourceReference("/subnets/s1")]);

        // Act
        var results = await Analyzer.Analyze([nsg]);

        // Assert
        results.Count.ShouldBe(1);
        results.Single().IssueDescription.ShouldBe("This Network Security Group has security rules that allow inbound traffic from the internet on common ports (e.g., 22, 3389).");
        results.Single().Severity.ShouldBe(SeverityLevel.High);
    }

    [Fact]
    public async Task Analyze_WithInternetInboundOnAllPorts_ReturnsAllPortsAnomaly()
    {
        // Arrange
        var nsg = CreateNetworkSecurityGroup(
            securityRules:
            [
                CreateSecurityRule(
                    sourceAddressPrefix: "*",
                    sourcePortRange: "1024-65535",
                    destinationPortRange: "*",
                    destinationAddressPrefix: "10.0.0.4")
            ],
            subnets: [new ResourceReference("/subnets/s1")]);

        // Act
        var results = await Analyzer.Analyze([nsg]);

        // Assert
        results.Count.ShouldBe(1);
        results.Single().IssueDescription.ShouldBe("This Network Security Group has security rules that allow inbound traffic from the internet on all ports.");
        results.Single().Severity.ShouldBe(SeverityLevel.High);
    }

    [Fact]
    public async Task Analyze_WithoutSubnets_ReturnsUnattachedAnomaly()
    {
        // Arrange
        var nsg = CreateNetworkSecurityGroup(
            securityRules:
            [
                CreateSecurityRule(sourceAddressPrefix: "10.0.0.0/24", destinationPortRange: "443")
            ],
            subnets: null);

        // Act
        var results = await Analyzer.Analyze([nsg]);

        // Assert
        results.Count.ShouldBe(1);
        results.Single().IssueDescription.ShouldBe("This Network Security Group is not attached to any subnets or network interfaces. This may give a false sense of security, as it is not actually protecting any resources.");
        results.Single().Severity.ShouldBe(SeverityLevel.Low);
    }

    [Fact]
    public async Task Analyze_WhenMultipleRulesMatch_ReturnsAllMatchingAnomalies()
    {
        // Arrange
        var nsg = CreateNetworkSecurityGroup(
            securityRules:
            [
                CreateSecurityRule(
                    sourceAddressPrefix: "*",
                    destinationAddressPrefix: "*",
                    sourcePortRange: "*",
                    destinationPortRange: "*")
            ],
            subnets: null);

        // Act
        var results = await Analyzer.Analyze([nsg]);

        // Assert
        results.Count.ShouldBe(3);
        var descriptions = results.Select(r => r.IssueDescription).ToArray();
        descriptions.ShouldContain("This Network Security Group has security rules that allow all inbound traffic.");
        descriptions.ShouldContain("This Network Security Group has security rules that allow inbound traffic from the internet on all ports.");
        descriptions.ShouldContain("This Network Security Group is not attached to any subnets or network interfaces. This may give a false sense of security, as it is not actually protecting any resources.");
    }

    [Fact]
    public async Task Analyze_WhenNoRulesMatch_ReturnsNoAnomalies()
    {
        // Arrange
        var nsg = CreateNetworkSecurityGroup(
            securityRules:
            [
                CreateSecurityRule(
                    access: "Deny",
                    sourceAddressPrefix: "10.0.0.0/24",
                    destinationAddressPrefix: "10.0.1.0/24",
                    sourcePortRange: "*",
                    destinationPortRange: "443")
            ],
            subnets: [new ResourceReference("/subnets/s1")]);

        // Act
        var results = await Analyzer.Analyze([nsg]);

        // Assert
        results.ShouldBeEmpty();
    }

    private static NetworkSecurityGroup CreateNetworkSecurityGroup(SecurityRule[]? securityRules, ResourceReference[]? subnets)
    {
        return new NetworkSecurityGroup(
            Id: "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Network/networkSecurityGroups/nsg1",
            Name: "nsg1",
            Type: "Microsoft.Network/networkSecurityGroups",
            Location: "westeurope",
            Tags: null,
            Properties: new NetworkSecurityGroupProperties(
                ProvisioningState: "Succeeded",
                ResourceGuid: Guid.NewGuid().ToString(),
                SecurityRules: securityRules,
                DefaultSecurityRules: null,
                NetworkInterfaces: null,
                Subnets: subnets));
    }

    private static SecurityRule CreateSecurityRule(
        string access = "Allow",
        string direction = "Inbound",
        string sourcePortRange = "*",
        string destinationPortRange = "*",
        string sourceAddressPrefix = "*",
        string destinationAddressPrefix = "*")
    {
        return new SecurityRule(
            Id: "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Network/networkSecurityGroups/nsg1/securityRules/r1",
            Name: "r1",
            Type: "Microsoft.Network/networkSecurityGroups/securityRules",
            Properties: new SecurityRuleProperties(
                ProvisioningState: "Succeeded",
                Description: null,
                Protocol: "*",
                SourcePortRange: sourcePortRange,
                DestinationPortRange: destinationPortRange,
                SourceAddressPrefix: sourceAddressPrefix,
                DestinationAddressPrefix: destinationAddressPrefix,
                Access: access,
                Priority: 100,
                Direction: direction,
                SourcePortRanges: null,
                DestinationPortRanges: null,
                SourceAddressPrefixes: null,
                DestinationAddressPrefixes: null));
    }
}
