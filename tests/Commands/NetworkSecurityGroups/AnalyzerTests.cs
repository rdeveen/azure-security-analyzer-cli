using AzureSecurityAnalyzer.Commands.NetworkSecurityGroups;
using AzureSecurityAnalyzer.ManagementApi;
using AwesomeAssertions;

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
        results.Count.Should().Be(1);
        results.Single().IssueDescription.Should().Be("This Network Security Group has no security rules defined.");
        results.Single().Severity.Should().Be(SeverityLevel.Medium);
    }

    [Fact]
    public async Task Analyze_WithAllowAllTrafficRule_ReturnsAllowAllTrafficAnomaly()
    {
        // Arrange
        var nsg = CreateNetworkSecurityGroup(
            securityRules:
            [
                CreateSecurityRule(
                    access: "Allow",
                    direction: "Inbound",
                    sourceAddressPrefix: "*",
                    destinationAddressPrefix: "*",
                    sourcePortRange: "*",
                    destinationPortRange: "*"),
                CreateSecurityRule(
                    access: "Allow",
                    direction: "Outbound",
                    sourceAddressPrefix: "*",
                    destinationAddressPrefix: "*",
                    sourcePortRange: "*",
                    destinationPortRange: "*")
            ],
            subnets: [new ResourceReference("/subnets/s1")]);

        // Act
        var results = await Analyzer.Analyze([nsg]);

        // Assert
        results.Count.Should().Be(3);
        results.Select(r => r.IssueDescription).Should().Contain("This Network Security Group has security rules that allow all inbound and all outbound traffic.");
        results.Select(r => r.IssueDescription).Should().Contain("This Network Security Group has security rules that allow inbound traffic from the internet on all ports.");
        results.Select(r => r.IssueDescription).Should().Contain("This Network Security Group has security rules that allow outbound traffic to the internet on all ports.");
    }

    [Fact]
    public async Task Analyze_WithAllowAllInboundTrafficRule_ReturnsAllowAllInboundTrafficAnomaly()
    {
        // Arrange
        var nsg = CreateNetworkSecurityGroup(
            securityRules:
            [
                CreateSecurityRule(
                    access: "Allow",
                    direction: "Inbound",
                    sourceAddressPrefix: "*",
                    destinationAddressPrefix: "*",
                    sourcePortRange: "*",
                    destinationPortRange: "*")
            ],
            subnets: [new ResourceReference("/subnets/s1")]);

        // Act
        var results = await Analyzer.Analyze([nsg]);

        // Assert
        results.Count.Should().Be(1);
        results.Select(r => r.IssueDescription).Should().Contain("This Network Security Group has security rules that allow inbound traffic from the internet on all ports.");
    }

    [Fact]
    public async Task Analyze_WithAllowAllOutboundTrafficRule_ReturnsAllowAllOutboundTrafficAnomaly()
    {
        // Arrange
        var nsg = CreateNetworkSecurityGroup(
            securityRules:
            [
                CreateSecurityRule(
                    access: "Allow",
                    direction: "Outbound",
                    sourceAddressPrefix: "*",
                    destinationAddressPrefix: "*",
                    sourcePortRange: "*",
                    destinationPortRange: "*")
            ],
            subnets: [new ResourceReference("/subnets/s1")]);

        // Act
        var results = await Analyzer.Analyze([nsg]);

        // Assert
        results.Count.Should().Be(1);
        results.Select(r => r.IssueDescription).Should().Contain("This Network Security Group has security rules that allow outbound traffic to the internet on all ports.");
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
        results.Count.Should().Be(1);
        results.Single().IssueDescription.Should().Be("This Network Security Group has security rules that allow inbound traffic from the internet on common ports (e.g., 22, 3389).");
        results.Single().Severity.Should().Be(SeverityLevel.High);
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
        results.Count.Should().Be(1);
        results.Single().IssueDescription.Should().Be("This Network Security Group has security rules that allow inbound traffic from the internet on all ports.");
        results.Single().Severity.Should().Be(SeverityLevel.High);
    }

    [Fact]
    public async Task Analyze_WithoutSubnetsAndNetworkInterfaces_ReturnsUnattachedAnomaly()
    {
        // Arrange
        var nsg = CreateNetworkSecurityGroup(
            securityRules:
            [
                CreateSecurityRule(sourceAddressPrefix: "10.0.0.0/24", destinationPortRange: "443")
            ],
            subnets: null,
            networkInterfaces: null);

        // Act
        var results = await Analyzer.Analyze([nsg]);

        // Assert
        results.Count.Should().Be(1);
        results.Single().IssueDescription.Should().Be("This Network Security Group is not attached to any subnets or network interfaces. This may give a false sense of security, as it is not actually protecting any resources.");
        results.Single().Severity.Should().Be(SeverityLevel.Low);
    }

    [Fact]
    public async Task Analyze_WithoutSubnetsButWithNetworkInterface_DoesNotReturnUnattachedAnomaly()
    {
        // Arrange
        var nsg = CreateNetworkSecurityGroup(
            securityRules:
            [
                CreateSecurityRule(sourceAddressPrefix: "10.0.0.0/24", destinationPortRange: "443")
            ],
            subnets: null,
            networkInterfaces: [new ResourceReference("/networkInterfaces/nic1")]);

        // Act
        var results = await Analyzer.Analyze([nsg]);

        // Assert
        results.Should().BeEmpty();
    }

    [Fact]
    public async Task Analyze_WhenMultipleRulesMatch_ReturnsAllMatchingAnomalies()
    {
        // Arrange
        var nsg = CreateNetworkSecurityGroup(
            securityRules:
            [
                CreateSecurityRule(
                    access: "Allow",
                    direction: "Inbound",
                    sourceAddressPrefix: "*",
                    destinationAddressPrefix: "*",
                    sourcePortRange: "*",
                    destinationPortRange: "*"),
                CreateSecurityRule(
                    access: "Allow",
                    direction: "Outbound",
                    sourceAddressPrefix: "*",
                    destinationAddressPrefix: "*",
                    sourcePortRange: "*",
                    destinationPortRange: "*")
            ],
            subnets: null,
            networkInterfaces: null);

        // Act
        var results = await Analyzer.Analyze([nsg]);

        // Assert
        results.Count.Should().Be(4);
        var descriptions = results.Select(r => r.IssueDescription).ToArray();
        descriptions.Should().Contain("This Network Security Group has security rules that allow all inbound and all outbound traffic.");
        descriptions.Should().Contain("This Network Security Group has security rules that allow inbound traffic from the internet on all ports.");
        descriptions.Should().Contain("This Network Security Group has security rules that allow outbound traffic to the internet on all ports.");
        descriptions.Should().Contain("This Network Security Group is not attached to any subnets or network interfaces. This may give a false sense of security, as it is not actually protecting any resources.");
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
        results.Should().BeEmpty();
    }

    private static NetworkSecurityGroup CreateNetworkSecurityGroup(
        SecurityRule[]? securityRules,
        ResourceReference[]? subnets,
        ResourceReference[]? networkInterfaces = null)
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
                NetworkInterfaces: networkInterfaces,
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
